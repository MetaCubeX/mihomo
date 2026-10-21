//go:build windows && (amd64 || 386)

package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/nat"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestWFPInterfaceMonitor(t *testing.T) {
	if os.Getenv("MIHOMO_WFP_TEST") != "1" {
		t.Skip("administrator driver test")
	}
	echo := &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)}
	listener, err := New(LC.Tun{InterceptMode: C.TunInterceptWFP, Stack: C.TunMips, AutoDetectInterface: true, RouteAddress: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}}, echo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if listener.networkUpdateMonitor == nil || listener.defaultInterfaceMonitor == nil || dialer.DefaultInterfaceFinder.Load() != listener.cDialerInterfaceFinder {
		t.Fatal("WFP did not register the shared interface monitor")
	}
	name := listener.cDialerInterfaceFinder.FindInterfaceName(netip.MustParseAddr("203.0.113.1"))
	if name == "" || name == "<invalid>" || name == "WinDivert" {
		t.Fatalf("invalid detected physical interface: %s", name)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if dialer.DefaultInterfaceFinder.Load() != nil {
		t.Fatal("WFP retained its interface finder after close")
	}
}

func TestWFPPolicy(t *testing.T) {
	if os.Getenv("MIHOMO_WFP_TEST") != "1" {
		t.Skip("administrator driver test")
	}
	for _, test := range []struct {
		name      string
		configure func(*LC.Tun)
	}{
		{"excluded-address", func(o *LC.Tun) { o.RouteExcludeAddress = []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")} }},
		{"outside-route", func(o *LC.Tun) { o.RouteAddress = []netip.Prefix{netip.MustParsePrefix("203.0.113.2/32")} }},
		{"excluded-port", func(o *LC.Tun) { o.ExcludeDstPort = []uint16{18473} }},
		{"excluded-range", func(o *LC.Tun) { o.ExcludeDstPortRange = []string{"18470:18479"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			echo := &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)}
			options := LC.Tun{InterceptMode: C.TunInterceptWFP, Stack: C.TunSystem, RouteAddress: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}}
			test.configure(&options)
			listener, err := New(options, echo)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			for _, network := range []string{"tcp4", "udp4"} {
				runWFPClient(t, "TestWFPBypassClient", network)
			}
			select {
			case metadata := <-echo.seen:
				t.Fatalf("excluded flow intercepted: %+v", metadata)
			default:
			}
		})
	}
	t.Run("loopback", func(t *testing.T) {
		echo := &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)}
		listener, err := New(LC.Tun{InterceptMode: C.TunInterceptWFP, Stack: C.TunSystem, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe::1/126")}, RouteAddress: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}, echo)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			t.Setenv("MIHOMO_WFP_CLIENT_ADDRESS", wfpLoopbackServer(t, network))
			runWFPClient(t, "TestWFPClient", network)
		}
		select {
		case <-echo.seen:
			t.Fatal("loopback traffic intercepted")
		default:
		}
	})
}

func TestWFPBypassClient(t *testing.T) {
	network := os.Getenv("MIHOMO_WFP_CLIENT")
	if network == "" {
		t.Skip("integration subprocess")
	}
	conn, err := net.DialTimeout(network, "203.0.113.1:18473", 200*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err = conn.Write([]byte("must bypass WFP")); err != nil {
		return
	}
	var reply [64]byte
	if n, err := conn.Read(reply[:]); n > 0 && err == nil {
		t.Fatal("excluded destination was echoed by WFP")
	}
}

func TestWFPHeldClient(t *testing.T) {
	if os.Getenv("MIHOMO_WFP_HELD_CLIENT") != "1" {
		t.Skip("integration subprocess")
	}
	conn, err := net.DialTimeout("tcp4", "203.0.113.1:18473", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Read(make([]byte, 1))
}

func TestWFPCloseActiveConnection(t *testing.T) {
	if os.Getenv("MIHOMO_WFP_TEST") != "1" {
		t.Skip("administrator driver test")
	}
	for _, stack := range wfpStacks() {
		t.Run(stack.String(), func(t *testing.T) {
			echo := &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)}
			listener, err := New(LC.Tun{InterceptMode: C.TunInterceptWFP, Stack: stack, RouteAddress: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}}, echo)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWFPHeldClient$")
			child.Env = append(os.Environ(), "MIHOMO_WFP_HELD_CLIENT=1")
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = child.Wait() }()
			select {
			case <-echo.seen:
			case <-time.After(6 * time.Second):
				t.Fatal("client did not reach handler")
			}
			closed := make(chan struct{})
			go func() { _ = listener.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatalf("%s close with active TCP blocked", stack)
			}
		})
	}
}
