package outbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/mihomo/transport/singsnell/snellv6"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/stretchr/testify/require"
)

const snellV6TestPSK = "mihomo-snell-v6-outbound-test-psk"

type snellV6EchoHandler struct{}

func (snellV6EchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose snell.CloseHandlerFunc) {
	go func() {
		var err error
		defer func() {
			_ = N.CloseWrite(conn)
			_ = conn.Close()
			onClose(err)
		}()
		var payload []byte
		payload, err = io.ReadAll(conn)
		if err != nil {
			return
		}
		_, err = conn.Write(payload)
	}()
}

func (snellV6EchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose snell.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		readWaitOptions := N.NewReadWaitOptions(conn, conn)
		for {
			buffer := readWaitOptions.NewPacketBuffer()
			dest, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			if err = conn.WritePacket(buffer, dest); err != nil {
				return
			}
		}
	}()
}

func startSnellV6Server(t *testing.T, mode snellv6.Mode) (host string, port int) {
	t.Helper()
	service, err := snellv6.NewService(snellv6.ServerOptions{
		PSK:     []byte(snellV6TestPSK),
		Mode:    mode,
		Handler: snellV6EchoHandler{},
	})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				if err := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), func(error) {}); err != nil {
					conn.Close()
				}
			}()
		}
	}()
	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err = strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

func newSnellV6Outbound(t *testing.T, mode string, reuse bool) *Snell {
	t.Helper()
	host, port := startSnellV6Server(t, mustParseV6Mode(t, mode))
	proxy, err := NewSnell(SnellOption{
		Name:    "snell-v6-" + mode,
		Server:  host,
		Port:    port,
		Psk:     snellV6TestPSK,
		Version: 6,
		UDP:     true,
		Reuse:   reuse,
		Mode:    mode,
	})
	require.NoError(t, err)
	t.Cleanup(func() { proxy.Close() })
	return proxy
}

func mustParseV6Mode(t *testing.T, mode string) snellv6.Mode {
	t.Helper()
	parsed, err := snellv6.ParseMode(mode)
	require.NoError(t, err)
	return parsed
}

func snellV6EchoTCP(t *testing.T, proxy *Snell) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		Host:    "example.com",
		DstPort: 443,
	})
	require.NoError(t, err)
	defer conn.Close()

	payload := make([]byte, 128*1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, N.CloseWrite(conn))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, received), "payload mismatch")
}

func TestSnellV6OutboundTCP(t *testing.T) {
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		t.Run(mode, func(t *testing.T) {
			snellV6EchoTCP(t, newSnellV6Outbound(t, mode, false))
		})
	}
}

func TestSnellV6OutboundTCPReuse(t *testing.T) {
	proxy := newSnellV6Outbound(t, "default", true)
	for round := 0; round < 3; round++ {
		snellV6EchoTCP(t, proxy)
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSnellV6OutboundUDP(t *testing.T) {
	proxy := newSnellV6Outbound(t, "default", false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	pc, err := proxy.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: 53,
	})
	require.NoError(t, err)
	defer pc.Close()

	for round := 0; round < 5; round++ {
		message := make([]byte, 1200)
		_, err = rand.Read(message)
		require.NoError(t, err)
		_, err = pc.WriteTo(message, target)
		require.NoError(t, err)

		received := make([]byte, 2048)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(10*time.Second)))
		n, from, err := pc.ReadFrom(received)
		require.NoError(t, err)
		require.Equal(t, target.String(), from.String())
		require.True(t, bytes.Equal(message, received[:n]), "round %d", round)
	}
}

func TestSnellV6OutboundValidation(t *testing.T) {
	base := func() SnellOption {
		return SnellOption{Name: "v6", Server: "127.0.0.1", Port: 1, Psk: snellV6TestPSK, Version: 6}
	}

	opt := base()
	opt.Psk = "short"
	_, err := NewSnell(opt)
	require.Error(t, err, "psk shorter than 12 bytes must be rejected")

	opt = base()
	opt.ObfsOpts = map[string]any{"mode": "http"}
	_, err = NewSnell(opt)
	require.Error(t, err, "v6 has no simple-obfs layer")

	opt = base()
	opt.Mode = "bogus"
	_, err = NewSnell(opt)
	require.Error(t, err, "unknown mode must be rejected")

	opt = base()
	opt.Version = 4
	opt.Mode = "unshaped"
	_, err = NewSnell(opt)
	require.Error(t, err, "mode is v6 only")

	opt = base()
	opt.Mode = "unshaped"
	proxy, err := NewSnell(opt)
	require.NoError(t, err)
	require.NoError(t, proxy.Close())
}
