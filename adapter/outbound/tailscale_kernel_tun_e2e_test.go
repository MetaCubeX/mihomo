//go:build with_gvisor && !no_tailscale && linux && tailscale_kernel_host_forward_e2e

package outbound

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTailscaleKernelHostForwardTUNConfigureE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel host-forward TUN e2e requires root or CAP_NET_ADMIN")
	}

	deviceName := fmt.Sprintf("mtse%06d", os.Getpid()%1000000)
	for _, route := range []struct {
		family string
		prefix string
	}{
		{family: "4", prefix: "100.64.0.0/10"},
		{family: "6", prefix: "fd7a:115c:a1e0::/48"},
	} {
		if out, err := ipRouteShow(route.family, route.prefix, deviceName); err == nil && strings.TrimSpace(out) != "" {
			t.Fatalf("test device route already exists for %s: %s", route.prefix, out)
		}
	}

	forwarder, err := newTailscaleKernelHostForwarder("kernel-e2e", TailscaleHostForwardOption{
		Enabled: true,
		Mode:    tailscaleHostForwardModeKernel,
		Device:  deviceName,
		MTU:     1280,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close() })

	if _, err := net.InterfaceByName(deviceName); err != nil {
		t.Fatalf("kernel host-forward interface was not created: %v", err)
	}

	v4 := netip.MustParseAddr("100.100.100.100")
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::1234")
	if err := forwarder.Configure(v4, v6); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"100.100.100.100/32", "fd7a:115c:a1e0::1234/128"} {
		if err := interfaceHasAddress(deviceName, want); err != nil {
			t.Fatal(err)
		}
	}
	for _, route := range []struct {
		family string
		prefix string
	}{
		{family: "4", prefix: "100.64.0.0/10"},
		{family: "6", prefix: "fd7a:115c:a1e0::/48"},
	} {
		out, err := ipRouteShow(route.family, route.prefix, deviceName)
		if err != nil {
			t.Fatalf("route lookup failed for %s: %v: %s", route.prefix, err, out)
		}
		if strings.TrimSpace(out) == "" {
			t.Fatalf("route for %s via %s was not installed", route.prefix, deviceName)
		}
	}

	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	eventuallyKernelTUN(t, 5*time.Second, 100*time.Millisecond, func() error {
		iface, err := net.InterfaceByName(deviceName)
		if err == nil {
			return fmt.Errorf("kernel host-forward interface still exists: %+v", iface)
		}
		return nil
	})
}

func interfaceHasAddress(deviceName, want string) error {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if addr.String() == want {
			return nil
		}
	}
	return fmt.Errorf("%s is missing address %s; got %v", deviceName, want, addrs)
}

func ipRouteShow(family, prefix, deviceName string) (string, error) {
	args := []string{"route", "show", prefix, "dev", deviceName}
	if family == "6" {
		args = append([]string{"-6"}, args...)
	}
	out, err := exec.Command("ip", args...).CombinedOutput()
	return string(out), err
}

func eventuallyKernelTUN(t *testing.T, timeout, interval time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err != nil {
			lastErr = err
			time.Sleep(interval)
			continue
		}
		return
	}
	if lastErr != nil {
		t.Fatal(lastErr)
	}
}
