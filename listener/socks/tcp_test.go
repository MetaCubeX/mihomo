package socks_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slowProxy is DIRECT with a slow handshake, like a remote node far away.
type slowProxy struct {
	C.ProxyAdapter
	name  string
	delay time.Duration
}

func (p *slowProxy) Name() string { return p.name }

func (p *slowProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return p.ProxyAdapter.DialContext(ctx, metadata)
}

// failProxy fails at once without the tunnel retrying.
type failProxy struct {
	C.ProxyAdapter
}

func (p *failProxy) Name() string { return "FAIL" }

func (p *failProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	return nil, resolver.ErrIPNotFound
}

// earlyProxy returns a conn whose protocol handshake is sent with the first write,
// like vmess/vless/shadowsocks do.
type earlyProxy struct {
	C.ProxyAdapter
	firstWrite chan []byte
}

func (p *earlyProxy) Name() string { return "EARLY" }

func (p *earlyProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := p.ProxyAdapter.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return &earlyConn{Conn: c, firstWrite: p.firstWrite}, nil
}

type earlyConn struct {
	C.Conn
	firstWrite chan []byte
	written    atomic.Bool
}

func (c *earlyConn) NeedHandshake() bool {
	return !c.written.Load()
}

func (c *earlyConn) Write(b []byte) (int, error) {
	if !c.written.Swap(true) {
		c.firstWrite <- append([]byte{}, b...)
	}
	return c.Conn.Write(b)
}

func setupTunnel(proxies ...C.ProxyAdapter) {
	m := map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}
	for _, proxy := range proxies {
		m[proxy.Name()] = adapter.NewProxy(proxy)
	}
	tunnel.UpdateProxies(m, nil)
	tunnel.OnRunning()
}

func listenSocks(t *testing.T, proxyName string) string {
	l, err := socks.NewWithConfig(
		LC.AuthServer{Enable: true, Listen: "127.0.0.1:0", AuthStore: authStore.Nil},
		inbound.NewListenConfig(), tunnel.Tunnel,
		inbound.WithInName("TEST-SOCKS"), inbound.WithSpecialProxy(proxyName),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l.Address()
}

func listenEcho(t *testing.T) netip.AddrPort {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(l.Addr().String())
}

func closedPort(t *testing.T) netip.AddrPort {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := netip.MustParseAddrPort(l.Addr().String())
	require.NoError(t, l.Close())
	return addr
}

// socks5Connect sends a CONNECT request and returns the REP field and how long the reply took.
func socks5Connect(t *testing.T, proxyAddr string, target netip.AddrPort) (net.Conn, byte, time.Duration) {
	c, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = c.Write([]byte{5, 1, 0})
	require.NoError(t, err)
	buf := make([]byte, 10)
	_, err = io.ReadFull(c, buf[:2])
	require.NoError(t, err)
	require.Equal(t, []byte{5, 0}, buf[:2])

	req := []byte{5, 1, 0, 1}
	req = append(req, target.Addr().AsSlice()...)
	req = binary.BigEndian.AppendUint16(req, target.Port())
	start := time.Now()
	_, err = c.Write(req)
	require.NoError(t, err)
	_, err = io.ReadFull(c, buf)
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.Equal(t, byte(5), buf[0])
	return c, buf[1], elapsed
}

func socks4Connect(t *testing.T, proxyAddr string, target netip.AddrPort) byte {
	c, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))

	req := []byte{4, 1}
	req = binary.BigEndian.AppendUint16(req, target.Port())
	req = append(req, target.Addr().AsSlice()...)
	req = append(req, 0) // empty USERID
	_, err = c.Write(req)
	require.NoError(t, err)
	buf := make([]byte, 8)
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err)
	require.Equal(t, byte(0), buf[0])
	return buf[1]
}

func assertEcho(t *testing.T, c net.Conn, data []byte) {
	_, err := c.Write(data)
	require.NoError(t, err)
	buf := make([]byte, len(data))
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err)
	assert.Equal(t, data, buf)
}

func TestSocks5ReplyAfterDial(t *testing.T) {
	const delay = 300 * time.Millisecond
	setupTunnel(&slowProxy{ProxyAdapter: outbound.NewDirect(), name: "SLOW", delay: delay})
	target := listenEcho(t)

	c, rep, elapsed := socks5Connect(t, listenSocks(t, "SLOW"), target)
	assert.Equal(t, byte(0), rep)
	assert.GreaterOrEqual(t, elapsed, delay, "reply must wait for the dial")
	assertEcho(t, c, []byte("ping"))
}

func TestSocks5ReplyDialFailure(t *testing.T) {
	setupTunnel()
	c, rep, _ := socks5Connect(t, listenSocks(t, "DIRECT"), closedPort(t))
	if runtime.GOOS == "windows" {
		assert.NotEqual(t, byte(0), rep) // WSAECONNREFUSED is not syscall.ECONNREFUSED
	} else {
		assert.Equal(t, byte(5), rep) // connection refused
	}
	_, err := c.Read(make([]byte, 1))
	assert.Error(t, err) // closed after the reply
}

func TestSocks5ReplyWithoutDial(t *testing.T) {
	setupTunnel()
	// the tunnel gives up before dialing, closing the conn must still reply
	_, rep, _ := socks5Connect(t, listenSocks(t, "NOT-EXIST"), listenEcho(t))
	assert.Equal(t, byte(1), rep) // general failure
}

func TestSocks4ReplyAfterDial(t *testing.T) {
	setupTunnel(&failProxy{ProxyAdapter: outbound.NewDirect()})
	assert.Equal(t, byte(90), socks4Connect(t, listenSocks(t, "DIRECT"), listenEcho(t)))
	assert.Equal(t, byte(91), socks4Connect(t, listenSocks(t, "FAIL"), listenEcho(t)))
}

func TestSocks5ReplyWithSniffer(t *testing.T) {
	const delay = time.Second
	setupTunnel(&slowProxy{ProxyAdapter: outbound.NewDirect(), name: "SLOW", delay: delay})
	target := listenEcho(t)

	ports, err := utils.NewUnsignedRanges[uint16](strconv.Itoa(int(target.Port())))
	require.NoError(t, err)
	dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{
		Enable:      true,
		Sniffers:    map[snifferTypes.Type]sniffer.SnifferConfig{snifferTypes.HTTP: {Ports: ports}},
		ParsePureIp: true,
	})
	require.NoError(t, err)
	tunnel.UpdateSniffer(dispatcher)
	t.Cleanup(func() {
		disabled, _ := sniffer.NewDispatcher(&sniffer.Config{})
		tunnel.UpdateSniffer(disabled)
	})

	// the sniffer needs the first payload before dialing, so the reply can't wait for the dial
	c, rep, elapsed := socks5Connect(t, listenSocks(t, "SLOW"), target)
	assert.Equal(t, byte(0), rep)
	assert.Less(t, elapsed, delay)
	assertEcho(t, c, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
}

func TestSocks5ReplyBeforeEarlyData(t *testing.T) {
	proxy := &earlyProxy{ProxyAdapter: outbound.NewDirect(), firstWrite: make(chan []byte, 1)}
	setupTunnel(proxy)

	c, rep, _ := socks5Connect(t, listenSocks(t, "EARLY"), listenEcho(t))
	assert.Equal(t, byte(0), rep)
	payload := []byte("client first")
	assertEcho(t, c, payload)
	// the payload sent after the reply still goes out together with the outbound handshake
	assert.Equal(t, payload, <-proxy.firstWrite)
}
