package inbound_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/nowhere"
	"github.com/metacubex/mihomo/tunnel"
)

func newNowhereTestProxy(t *testing.T, routing C.Tunnel, up, down string, extra map[string]any) C.Proxy {
	t.Helper()
	config := map[string]any{
		"type": "nowhere", "name": "nw-in", "listen": "127.0.0.1", "port": 0,
		"password": "secret", "certificate": tlsCertificate, "private-key": tlsPrivateKey, "morph": true,
		"network": []string{"tcp", "udp"},
	}
	for key, value := range extra {
		config[key] = value
	}
	in, err := listener.ParseListener(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = in.Listen(routing); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	addresses := strings.Split(in.Address(), ",")
	address := netip.MustParseAddrPort(addresses[0])
	quicAddress := netip.MustParseAddrPort(addresses[len(addresses)-1])
	out, err := adapter.ParseProxy(map[string]any{
		"type": "nowhere", "name": "nw-out", "server": "127.0.0.1", "port": int(address.Port()),
		"udp-port": int(quicAddress.Port()), "password": "secret", "fingerprint": tlsFingerprint,
		"up": up, "down": down, "mux": true, "morph": true, "udp": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func TestInboundNowhereRouting(t *testing.T) {
	oldMode, oldProxies, oldStatus, oldProcess := tunnel.Mode(), tunnel.Proxies(), tunnel.Status(), tunnel.FindProcessMode()
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
	tunnel.SetMode(tunnel.Direct)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.SetMode(oldMode)
		tunnel.UpdateProxies(oldProxies, nil)
		tunnel.SetFindProcessMode(oldProcess)
		switch oldStatus {
		case tunnel.Running:
			tunnel.OnRunning()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		default:
			tunnel.OnSuspend()
		}
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var targets []net.PacketConn
	for i := 0; i < 2; i++ {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		targets = append(targets, p)
		go func() {
			b := make([]byte, 65535)
			for {
				n, a, err := p.ReadFrom(b)
				if err != nil {
					return
				}
				_, _ = p.WriteTo(b[:n], a)
			}
		}()
	}
	for _, up := range []string{"tcp", "udp"} {
		for _, down := range []string{"tcp", "udp"} {
			t.Run(up+"-"+down, func(t *testing.T) {
				inConfig := make(map[string]any)
				if up == "tcp" && down == "udp" {
					probe, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					inConfig["udp-port"] = int(probe.LocalAddr().(*net.UDPAddr).Port)
					probe.Close()
				}
				out := newNowhereTestProxy(t, tunnel.Tunnel, up, down, inConfig)
				metadata := &C.Metadata{NetWork: C.TCP}
				if err = metadata.SetRemoteAddress(l.Addr().String()); err != nil {
					t.Fatal(err)
				}
				conn, err := out.DialContext(context.Background(), metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := []byte("routed through mihomo")
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal(payload, reply) {
					t.Fatal(err, reply)
				}
				conn.Close()
				metadata = &C.Metadata{NetWork: C.UDP}
				_ = metadata.SetRemoteAddress(targets[0].LocalAddr().String())
				pc, err := out.ListenPacketContext(context.Background(), metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
				for _, target := range targets {
					for _, body := range [][]byte{{}, payload, bytes.Repeat([]byte("UDP"), 2000)} {
						if _, err = pc.WriteTo(body, target.LocalAddr()); err != nil {
							t.Fatal(err)
						}
						b := make([]byte, 65535)
						n, addr, err := pc.ReadFrom(b)
						if err != nil || !bytes.Equal(body, b[:n]) || addr.String() != target.LocalAddr().String() {
							t.Fatal(n, addr, err)
						}
						if _, ok := addr.(*net.UDPAddr); !ok {
							t.Fatalf("UDP reply address is %T, want *net.UDPAddr", addr)
						}
					}
				}
				pc.Close()
				// Both TCP and UDP must reject exhausted native forwarding budgets.
				for _, network := range []C.NetWork{C.TCP, C.UDP} {
					m := metadata.Clone()
					m.NetWork = network
					m.Type = C.NOWHERE
					m.NowhereHops = 1
					var err error
					if network == C.TCP {
						_, err = out.DialContext(context.Background(), m)
					} else {
						_, err = out.ListenPacketContext(context.Background(), m)
					}
					var setup nowhere.SetupError
					if !errors.As(err, &setup) || byte(setup) != nowhere.FlowLimit {
						t.Fatalf("%s budget: %v", network, err)
					}
				}
			})
		}
	}
}

func TestInboundNowhereMetadata(t *testing.T) {
	for _, carrier := range []string{"tcp", "udp"} {
		t.Run(carrier, func(t *testing.T) {
			metadataCh := make(chan *C.Metadata, 8)
			routing := &TestTunnel{
				HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
					defer conn.Close()
					metadataCh <- metadata
					_, _ = io.Copy(conn, conn)
				},
				HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
					defer packet.Drop()
					metadataCh <- metadata
					// No OS UDP target: exercise the full wire size independently
					// of the host's UDP send-buffer limit.
					_, _ = packet.WriteBack(packet.Data(), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:53")))
				},
			}
			out := newNowhereTestProxy(t, routing, carrier, carrier, map[string]any{"rule": "nw-rule", "proxy": "nw-proxy"})
			checkMetadata := func(network C.NetWork) {
				t.Helper()
				select {
				case m := <-metadataCh:
					if m.NetWork != network || m.Type != C.NOWHERE || m.NowhereHops != 6 ||
						m.InName != "nw-in" || m.SpecialRules != "nw-rule" || m.SpecialProxy != "nw-proxy" ||
						!m.SrcIP.IsLoopback() || m.SrcPort == 0 || !m.InIP.IsLoopback() || m.InPort == 0 {
						t.Fatalf("lost inbound metadata: %+v", m)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("inbound did not reach the standard tunnel interface")
				}
			}
			metadata := &C.Metadata{NetWork: C.TCP, Type: C.NOWHERE, NowhereHops: 7}
			_ = metadata.SetRemoteAddress("echo.test:53")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := out.DialContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			// The handler can read immediately without waiting for a tunnel
			// handshake callback (which custom embedders do not implement).
			if _, err = conn.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 5)
			if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != "hello" {
				t.Fatal(err, reply)
			}
			checkMetadata(C.TCP)
			conn.Close()

			metadata = &C.Metadata{NetWork: C.UDP, Type: C.NOWHERE, NowhereHops: 7}
			_ = metadata.SetRemoteAddress("127.0.0.1:53")
			pc, err := out.ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			for _, size := range []int{0, 65535} {
				payload := bytes.Repeat([]byte{42}, size)
				if _, err = pc.WriteTo(payload, metadata.UDPAddr()); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 65535)
				n, _, err := pc.ReadFrom(b)
				if err != nil || !bytes.Equal(payload, b[:n]) {
					t.Fatalf("UDP size %d: got %d, %v", size, n, err)
				}
				checkMetadata(C.UDP)
			}
		})
	}
}

func TestNowhereConfigurationValidation(t *testing.T) {
	for _, extra := range []map[string]any{{"password": ""}, {"up": "quic"}, {"down": "invalid"}, {"port": 70000}, {"tcp-port": -1}, {"morph-prelude": "invalid"}} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			m := map[string]any{"type": "nowhere", "name": "nw", "server": "localhost", "port": 443, "password": "secret"}
			for k, v := range extra {
				m[k] = v
			}
			if _, err := adapter.ParseProxy(m); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	if _, err := listener.ParseListener(map[string]any{"type": "nowhere", "name": "nw", "password": "secret"}); err == nil {
		t.Fatal("accepted missing certificate")
	}
	if typ, err := C.ParseType("NOWHERE"); err != nil || *typ != C.NOWHERE {
		t.Fatal(typ, err)
	}
}

// Record configured ports without depending on fixed ports being available.
// Failing UDP startup also exercises cleanup of the already bound TCP socket.
type nowhereFailingListenConfig struct {
	tcpAddress string
	udpAddress string
	listener   net.Listener
	err        error
}

func (c *nowhereFailingListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	c.tcpAddress = address
	var err error
	c.listener, err = (&net.ListenConfig{}).Listen(ctx, network, "127.0.0.1:0")
	return c.listener, err
}

func (c *nowhereFailingListenConfig) ListenPacket(_ context.Context, _, address string) (net.PacketConn, error) {
	c.udpAddress = address
	return nil, c.err
}

func TestNowhereNetworks(t *testing.T) {
	for _, test := range []struct {
		name     string
		networks any
		tcp, udp bool
		invalid  bool
	}{
		{name: "default", tcp: true, udp: true},
		{name: "empty", networks: []any{}, tcp: true, udp: true},
		{name: "tcp", networks: []any{"tcp"}, tcp: true},
		{name: "udp", networks: []any{"udp"}, udp: true},
		{name: "both", networks: []any{"tcp", "udp"}, tcp: true, udp: true},
		{name: "reversed", networks: []any{"udp", "tcp"}, tcp: true, udp: true},
		{name: "duplicate", networks: []any{"tcp", "tcp"}, tcp: true},
		{name: "unknown", networks: []any{"tcp", "quic"}, invalid: true},
		{name: "mix", networks: []any{"mix"}, invalid: true},
		{name: "legacy-mix", networks: "mix", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := map[string]any{
				"type": "nowhere", "name": "nw-network", "listen": "127.0.0.1", "port": 0,
				"password": "secret", "certificate": tlsCertificate, "private-key": tlsPrivateKey,
			}
			if test.networks != nil {
				config["network"] = test.networks
			}
			in, err := listener.ParseListener(config)
			if test.invalid {
				if err == nil {
					t.Fatal("accepted invalid network")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			lc := &nowhereFailingListenConfig{err: errors.New("UDP bind failed")}
			in.Config().(*inbound.NowhereOption).ListenConfigForAPI = lc
			err = in.Listen(&TestTunnel{})
			if lc.listener != nil {
				defer lc.listener.Close()
			}
			if (test.udp && !errors.Is(err, lc.err)) || (!test.udp && err != nil) {
				t.Fatalf("unexpected listen result: %v", err)
			}
			if (lc.tcpAddress != "") != test.tcp || (lc.udpAddress != "") != test.udp {
				t.Fatalf("unexpected listeners: TCP %q, UDP %q", lc.tcpAddress, lc.udpAddress)
			}
		})
	}
}

func TestNowhereListenerPortsAndCleanup(t *testing.T) {
	lc := &nowhereFailingListenConfig{err: errors.New("UDP bind failed")}
	in, err := inbound.NewNowhere(&inbound.NowhereOption{
		BaseOption: inbound.BaseOption{NameStr: "nw-ports", Listen: "127.0.0.1", Port: "2077", ListenConfigForAPI: lc},
		TCPPort:    2078,
		Network:    []string{"tcp", "udp"},
		Password:   "secret", Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err = in.Listen(&TestTunnel{}); !errors.Is(err, lc.err) {
		t.Fatalf("expected UDP bind failure, got %v", err)
	}
	if lc.listener == nil {
		t.Fatal("TCP listener was not created")
	}
	defer lc.listener.Close()
	if lc.tcpAddress != "127.0.0.1:2078" || lc.udpAddress != "127.0.0.1:2077" {
		t.Fatalf("carrier ports crossed: TCP %s, UDP %s", lc.tcpAddress, lc.udpAddress)
	}
	_ = lc.listener.(*net.TCPListener).SetDeadline(time.Now())
	if conn, err := lc.listener.Accept(); !errors.Is(err, net.ErrClosed) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("TCP listener not closed after UDP bind failure: %v", err)
	}
}
