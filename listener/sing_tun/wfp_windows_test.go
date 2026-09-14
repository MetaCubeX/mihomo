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
	"path/filepath"
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
	client := wfpTestClient(t)
	stacks := []C.TUNStack{C.TunSystem}
	if tun.WithGVisor {
		stacks = append(stacks, C.TunMixed, C.TunGvisor)
	}
	for _, stack := range stacks {
		t.Run(stack.String(), func(t *testing.T) { testWFPStack(t, stack, client) })
	}
}

// A separate executable prevents the relay's firewall rule from also allowing the client.
func wfpTestClient(t *testing.T) string {
	t.Helper()
	input, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wfp-client.exe")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testWFPStack(t *testing.T, stack C.TUNStack, client string) {
	echo := &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)}
	options := LC.Tun{Driver: "wfp", Stack: stack, RouteAddress: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}}
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
				runWFPClient(t, client, "TestWFPClient", network)
				select {
				case metadata := <-echo.seen:
					destination := "198.18.0.1"
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
		conn, err := net.DialTimeout("tcp4", "198.18.0.1:18473", 500*time.Millisecond)
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
		options.DNSHijack = []string{"any:53"}
		options.Inet6Address = nil
		l, err := New(options, echo)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		for _, network := range networks {
			t.Run(network, func(t *testing.T) {
				runWFPClient(t, client, "TestWFPDNSClient", network)
			})
		}
	})
}

func runWFPClient(t *testing.T, client, test, network string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, client, "-test.run=^"+test+"$")
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
	destination := "198.18.0.1:18473"
	if network[len(network)-1] == '6' {
		destination = "[2001:db8::1]:18473"
	}
	conn, err := net.DialTimeout(network, destination, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	repeat := 40
	if network[:3] == "tcp" {
		repeat = 1000
	}
	payload := bytes.Repeat([]byte("mihomo WFP TCP/UDP round trip"), repeat)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if network[:3] == "tcp" {
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("incorrect reply: %q", reply)
	}
	if network[:3] == "tcp" {
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("TCP close handshake failed: %v", err)
		}
	}
}
