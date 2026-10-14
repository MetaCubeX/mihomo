//go:build windows && (amd64 || 386)

package sing_tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/nat"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	MDNS "github.com/metacubex/mihomo/dns"
	LC "github.com/metacubex/mihomo/listener/config"

	tun "github.com/metacubex/sing-tun"
)

type wfpEchoTunnel struct {
	table C.NatTable
	seen  chan *C.Metadata
}

func (e *wfpEchoTunnel) NatTable() C.NatTable { return e.table }
func (e *wfpEchoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	e.seen <- metadata
	io.Copy(conn, conn)
}
func (e *wfpEchoTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	defer packet.Drop()
	e.seen <- metadata
	packet.WriteBack(packet.Data(), &net.UDPAddr{IP: metadata.DstIP.AsSlice(), Port: int(metadata.DstPort)})
}

func TestWFPIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_WFP_TEST") != "1" {
		t.Skip("set MIHOMO_WFP_TEST=1 as administrator to load the embedded driver")
	}
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 256})
	if err != nil {
		t.Fatal(err)
	}
	previous := resolver.DefaultService
	resolver.DefaultService = MDNS.NewService(MDNS.NewResolver(MDNS.Config{}), MDNS.NewEnhancer(MDNS.EnhancerConfig{
		EnhancedMode: C.DNSFakeIP, FakeIPPool: pool, FakeIPSkipper: &fakeip.Skipper{}, FakeIPTTL: 1,
	}))
	defer func() { resolver.DefaultService = previous }()
	for _, stack := range wfpStacks() {
		t.Run(stack.String(), func(t *testing.T) { testWFPStack(t, stack) })
	}
}

func wfpStacks() []C.TUNStack {
	stacks := []C.TUNStack{C.TunSystem, C.TunMips}
	if tun.WithGVisor {
		stacks = append(stacks, C.TunMixed, C.TunGvisor)
	}
	return stacks
}

func testWFPStack(t *testing.T, stack C.TUNStack) {
	echo := &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)}
	options := LC.Tun{InterceptMode: C.TunInterceptWFP, Stack: stack, RouteAddress: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}}
	networks := []string{"tcp4", "udp4"}
	if os.Getenv("MIHOMO_WFP_TEST_IPV6") == "1" {
		options.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fdfe::1/126")}
		options.RouteAddress = append(options.RouteAddress, netip.MustParsePrefix("2001:db8::1/128"))
		networks = append(networks, "tcp6", "udp6")
	}
	t.Run("traffic", func(t *testing.T) {
		l, err := New(options, echo)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		for _, network := range networks {
			t.Run(network, func(t *testing.T) {
				runWFPClient(t, "TestWFPClient", network)
				select {
				case metadata := <-echo.seen:
					destination := "203.0.113.1"
					if network[len(network)-1] == '6' {
						destination = "2001:db8::1"
					}
					if metadata.DstIP.String() != destination || metadata.DstPort != 18473 {
						t.Fatalf("original destination lost: %+v", metadata)
					}
				default:
					t.Fatal("packet did not reach mihomo tunnel")
				}
			})
		}
		conn, err := net.DialTimeout("tcp4", "203.0.113.1:18473", 500*time.Millisecond)
		if err == nil {
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			payload := []byte{0}
			conn.Write(payload)
			io.ReadFull(conn, payload)
			conn.Close()
		}
		select {
		case <-echo.seen:
			t.Fatal("the listener's own connection was intercepted")
		default:
		}
	})
	t.Run("dns", func(t *testing.T) {
		options.DNSHijack = []string{"203.0.113.1:53"}
		if os.Getenv("MIHOMO_WFP_TEST_IPV6") == "1" {
			options.DNSHijack = append(options.DNSHijack, "[2001:db8::1]:53")
		}
		options.Inet6Address = nil
		options.RouteExcludeAddress = options.RouteAddress
		options.RouteAddress = []netip.Prefix{netip.MustParsePrefix("203.0.113.2/32")}
		l, err := New(options, echo)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		for _, network := range networks {
			t.Run(network, func(t *testing.T) {
				runWFPClient(t, "TestWFPDNSClient", network)
			})
		}
	})
}

func runWFPClient(t *testing.T, test, network string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+test+"$")
	child.Env = append(os.Environ(), "MIHOMO_WFP_CLIENT="+network)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", test, err, output)
	}
}

func TestWFPClient(t *testing.T) {
	network := os.Getenv("MIHOMO_WFP_CLIENT")
	if network == "" {
		t.Skip("integration-test subprocess")
	}
	destination := "203.0.113.1:18473"
	if network[len(network)-1] == '6' {
		destination = "[2001:db8::1]:18473"
	}
	if address := os.Getenv("MIHOMO_WFP_CLIENT_ADDRESS"); address != "" {
		destination = address
	}
	conn, err := wfpClientDialer(network, destination).Dial(network, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	repeat := 40
	if network[:3] == "tcp" {
		repeat = 1 << 15
	}
	payload := bytes.Repeat([]byte("mihomo WFP TCP/UDP round trip"), repeat)
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if err == nil && network[:3] == "tcp" {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		written <- err
	}()
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatal("incorrect reply")
	}
	if network[:3] == "tcp" {
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("TCP close handshake failed: %v", err)
		}
	}
}

func wfpClientDialer(network, destination string) *net.Dialer {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	// Bind the configured source for the IPv6 test destination.
	if source := os.Getenv("MIHOMO_WFP_TEST_LOCAL_IPV6"); source != "" {
		remote, err := netip.ParseAddrPort(destination)
		if err == nil && remote.Addr() == netip.MustParseAddr("2001:db8::1") {
			if network == "tcp6" {
				dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
			}
			if network == "udp6" {
				dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
			}
		}
	}
	return dialer
}

func wfpLoopbackServer(t *testing.T, network string) string {
	t.Helper()
	address := "127.0.0.1:0"
	if strings.HasSuffix(network, "6") {
		address = "[::1]:0"
	}
	if strings.HasPrefix(network, "tcp") {
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.Copy(conn, conn)
		}()
		return listener.Addr().String()
	}
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		n, addr, err := conn.ReadFrom(buffer)
		if err == nil {
			_, _ = conn.WriteTo(buffer[:n], addr)
		}
	}()
	return conn.LocalAddr().String()
}
