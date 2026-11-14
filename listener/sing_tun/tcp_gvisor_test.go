//go:build with_gvisor

package sing_tun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	tun "github.com/metacubex/sing-tun"
)

type gvisorTestProxy struct {
	*outbound.Base
	dial func(context.Context, *C.Metadata) (C.Conn, error)
}

func (p *gvisorTestProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	return p.dial(ctx, metadata)
}

func installGvisorTestProxy(t *testing.T, proxy C.ProxyAdapter) {
	t.Helper()
	oldMode, oldStatus := tunnel.Mode(), tunnel.Status()
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(proxy)}, nil)
	tunnel.SetMode(tunnel.Direct)
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.UpdateProxies(oldProxies, oldProviders)
		tunnel.SetMode(oldMode)
		switch oldStatus {
		case tunnel.Suspend:
			tunnel.OnSuspend()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		case tunnel.Running:
			tunnel.OnRunning()
		}
	})
}

// Run the actual sing-tun TCP forwarder, listener and Mihomo tunnel between two
// in-memory IP stacks. No administrator privileges, TUN routes or public server
// are needed. Observe TCP RST on the wire as well as the client's read result.
func newGvisorTestClient(t *testing.T, ipv6 bool) (net.Conn, *atomic.Bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	clientLink, serverLink := channel.New(32, 1500, ""), channel.New(32, 1500, "")
	clientStack, err := tun.NewGVisorStack(clientLink)
	if err != nil {
		t.Fatal(err)
	}
	serverStack, err := tun.NewGVisorStack(serverLink)
	if err != nil {
		t.Fatal(err)
	}
	base, err := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: tunnel.Tunnel, Type: C.TUN})
	if err != nil {
		t.Fatal(err)
	}
	handler := &ListenerHandler{ListenerHandler: base}
	serverStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(ctx, serverStack, handler).HandlePacket)

	source, target := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	protocol := header.IPv4ProtocolNumber
	prefix := 32
	if ipv6 {
		source, target = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::1")
		protocol, prefix = header.IPv6ProtocolNumber, 128
	}
	if err := clientStack.AddProtocolAddress(tun.DefaultNIC, tcpip.ProtocolAddress{
		Protocol:          protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tun.AddressFromAddr(source), PrefixLen: prefix},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}

	resetSeen := &atomic.Bool{}
	var pumps sync.WaitGroup
	forward := func(from, to *channel.Endpoint, observe bool) {
		defer pumps.Done()
		for {
			packet := from.ReadContext(ctx)
			if packet == nil {
				return
			}
			if observe && packet.TransportProtocolNumber == tcp.ProtocolNumber {
				if header.TCP(packet.TransportHeader().Slice()).Flags()&header.TCPFlagRst != 0 {
					resetSeen.Store(true)
				}
			}
			incoming := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: packet.ToBuffer()})
			to.InjectInbound(packet.NetworkProtocolNumber, incoming)
			incoming.DecRef()
			packet.DecRef()
		}
	}
	pumps.Add(2)
	go forward(clientLink, serverLink, false)
	go forward(serverLink, clientLink, true)
	t.Cleanup(func() {
		cancel()
		for _, s := range []*stack.Stack{clientStack, serverStack} {
			s.Close()
			for _, endpoint := range s.CleanupEndpoints() {
				endpoint.Abort()
			}
		}
		pumps.Wait()
		clientLink.Close()
		serverLink.Close()
	})
	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	conn, err := gonet.DialContextTCP(dialCtx, clientStack, tcpip.FullAddress{
		NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(target), Port: 443,
	}, protocol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn, resetSeen
}

func TestGvisorUpstreamDialFailureSendsReset(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			proxy := &gvisorTestProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "DIRECT", Type: C.Direct})}
			proxy.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
				// A terminal dial failure avoids retries and external networking.
				return nil, resolver.ErrIPVersion
			}
			installGvisorTestProxy(t, proxy)
			conn, resetSeen := newGvisorTestClient(t, ipv6)
			_, err := conn.Read(make([]byte, 1))
			if err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("upstream dial failure reached client as %v; want TCP reset", err)
			}
			if !resetSeen.Load() {
				t.Fatalf("no TCP RST observed; read returned %v", err)
			}
		})
	}
}

func TestGvisorSuccessfulRelayKeepsGracefulEOF(t *testing.T) {
	proxy := &gvisorTestProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "DIRECT", Type: C.Direct})}
	proxy.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = io.CopyN(server, server, 4)
		}()
		return outbound.NewConn(client, proxy), nil
	}
	installGvisorTestProxy(t, proxy)
	conn, resetSeen := newGvisorTestClient(t, true)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "ping" {
		t.Fatalf("relay returned %q, %v; want echo and graceful EOF", data, err)
	}
	if resetSeen.Load() {
		t.Fatal("successful relay sent a reset")
	}
}

func TestGvisorRetriedDialFailureSendsReset(t *testing.T) {
	var attempts atomic.Int32
	proxy := &gvisorTestProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "DIRECT", Type: C.Direct})}
	proxy.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
		attempts.Add(1)
		return nil, syscall.ENETUNREACH
	}
	installGvisorTestProxy(t, proxy)
	conn, resetSeen := newGvisorTestClient(t, true)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := conn.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) || !resetSeen.Load() {
		t.Fatalf("retried dial failure returned %v, reset=%v", err, resetSeen.Load())
	}
	if attempts.Load() < 2 {
		t.Fatal("expected to exercise the tunnel's retry path")
	}
}

func TestGvisorRejectKeepsGracefulEOF(t *testing.T) {
	installGvisorTestProxy(t, outbound.NewReject())
	conn, resetSeen := newGvisorTestClient(t, true)
	_, err := conn.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("REJECT returned %v; want existing graceful EOF", err)
	}
	if resetSeen.Load() {
		t.Fatal("REJECT unexpectedly sent a reset")
	}
}
