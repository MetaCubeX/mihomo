package tunnel_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

type recordingPacketConn struct {
	writes    chan netip.AddrPort
	closed    chan struct{}
	closeOnce sync.Once
}

func newRecordingPacketConn() *recordingPacketConn {
	return &recordingPacketConn{writes: make(chan netip.AddrPort, 64), closed: make(chan struct{})}
}

func (c *recordingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes <- addr.(*net.UDPAddr).AddrPort()
	return len(p), nil
}

func (c *recordingPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *recordingPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *recordingPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type recordingProxy struct {
	*outbound.Base
	conn *recordingPacketConn
}

func (p *recordingProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return outbound.NewPacketConn(p.conn, p), nil
}

type testUDPPacket struct {
	local net.Addr
}

func (p *testUDPPacket) Data() []byte                                         { return []byte("test") }
func (p *testUDPPacket) WriteBack(b []byte, addr net.Addr) (n int, err error) { return len(b), nil }
func (p *testUDPPacket) Drop()                                                {}
func (p *testUDPPacket) LocalAddr() net.Addr                                  { return p.local }

// setupUDPRules routes "PROXY" to a recording outbound and restores the tunnel state afterwards.
func setupUDPRules(t *testing.T, rules ...C.Rule) *recordingPacketConn {
	conn := newRecordingPacketConn()
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	oldRules, oldRuleProviders := tunnel.Rules(), tunnel.RuleProviders()
	oldStatus, oldMode := tunnel.Status(), tunnel.Mode()
	tunnel.UpdateProxies(map[string]C.Proxy{
		"PROXY": adapter.NewProxy(&recordingProxy{
			Base: outbound.NewBase(outbound.BaseOption{Name: "PROXY", Type: C.Direct, UDP: true}),
			conn: conn,
		}),
		"REJECT":      adapter.NewProxy(outbound.NewReject()),
		"REJECT-DROP": adapter.NewProxy(outbound.NewRejectDrop()),
	}, nil)
	tunnel.UpdateRules(rules, nil, nil)
	tunnel.SetMode(tunnel.Rule)
	tunnel.OnRunning()
	t.Cleanup(func() {
		_ = conn.Close()
		switch oldStatus {
		case tunnel.Suspend:
			tunnel.OnSuspend()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		}
		tunnel.SetMode(oldMode)
		tunnel.UpdateProxies(oldProxies, oldProviders)
		tunnel.UpdateRules(oldRules, nil, oldRuleProviders)
	})
	return conn
}

func mustRule(rule C.Rule, err error) C.Rule {
	if err != nil {
		panic(err)
	}
	return rule
}

// sendUDP sends one packet per destination, all from the same local address (one association).
func sendUDP(local netip.AddrPort, destinations ...string) {
	for _, destination := range destinations {
		target := netip.MustParseAddrPort(destination)
		tunnel.Tunnel.HandleUDPPacket(&testUDPPacket{local: net.UDPAddrFromAddrPort(local)}, &C.Metadata{
			NetWork: C.UDP,
			Type:    C.SOCKS5,
			SrcIP:   local.Addr(),
			SrcPort: local.Port(),
			DstIP:   target.Addr(),
			DstPort: target.Port(),
		})
	}
}

// expectWrites checks the destinations the outbound wrote to. The last expected write is
// for the last packet sent, so once it arrived every earlier packet has been processed.
func expectWrites(t *testing.T, conn *recordingPacketConn, expected ...string) {
	t.Helper()
	var got []string
	timeout := time.After(5 * time.Second)
	for len(got) < len(expected) {
		select {
		case addr := <-conn.writes:
			got = append(got, addr.String())
		case <-timeout:
			t.Fatalf("writes = %v, want %v", got, expected)
		}
	}
	select {
	case addr := <-conn.writes:
		got = append(got, addr.String())
	default:
	}
	if len(got) != len(expected) {
		t.Fatalf("writes = %v, want %v", got, expected)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("writes = %v, want %v", got, expected)
		}
	}
}

func TestUDPAssociationLaterDestinationRejected(t *testing.T) {
	conn := setupUDPRules(t,
		mustRule(RC.NewIPCIDR("192.0.2.0/24", "PROXY")),
		mustRule(RC.NewIPCIDR("10.0.0.0/8", "REJECT")),
		mustRule(RC.NewIPCIDR("172.16.0.0/12", "REJECT-DROP")),
		RC.NewMatch("REJECT"),
	)
	sendUDP(netip.MustParseAddrPort("127.0.0.1:50001"),
		"192.0.2.1:53",
		"10.0.0.1:53",     // IP-CIDR REJECT
		"172.16.0.1:53",   // IP-CIDR REJECT-DROP
		"198.51.100.1:53", // MATCH REJECT
		"10.0.0.1:53",     // again, from the cache
		"192.0.2.2:53",
	)
	expectWrites(t, conn, "192.0.2.1:53", "192.0.2.2:53")
}

func TestUDPAssociationLaterPortRejected(t *testing.T) {
	conn := setupUDPRules(t,
		mustRule(RC.NewPort("22", "REJECT", C.DstPort)),
		RC.NewMatch("PROXY"),
	)
	sendUDP(netip.MustParseAddrPort("127.0.0.1:50002"), "192.0.2.1:53", "192.0.2.1:22", "192.0.2.1:54")
	expectWrites(t, conn, "192.0.2.1:53", "192.0.2.1:54")
}

func TestUDPAssociationAllowedDestinations(t *testing.T) {
	conn := setupUDPRules(t,
		mustRule(RC.NewIPCIDR("192.0.2.0/24", "PROXY")),
		mustRule(RC.NewIPCIDR("198.51.100.0/24", "PROXY")),
		RC.NewMatch("REJECT"),
	)
	destinations := []string{"192.0.2.1:53", "192.0.2.1:443", "198.51.100.7:3478", "192.0.2.1:53", "192.0.2.2:53"}
	sendUDP(netip.MustParseAddrPort("127.0.0.1:50003"), destinations...)
	expectWrites(t, conn, destinations...)
}
