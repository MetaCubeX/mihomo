package dialer

// These tests exercise the endpoint-scoped interface-selection seam without
// opening sockets or creating a TUN device. They install a deterministic
// interface finder and route-exclusion set, assert the selected interface, and
// restore the package-level defaults after each test so they remain isolated.
import (
	"net/netip"
	"testing"

	"go4.org/netipx"
)

type interfaceFinderFunc func(netip.Addr) string

func (f interfaceFinderFunc) FindInterfaceName(destination netip.Addr) string {
	return f(destination)
}

func TestProxyEndpointRouteExcludeSelectsSystemRoute(t *testing.T) {
	endpoint := netip.MustParseAddr("100.64.0.1")
	excludeBuilder := netipx.IPSetBuilder{}
	excludeBuilder.AddPrefix(netip.MustParsePrefix("100.64.0.0/10"))
	excludeSet, err := excludeBuilder.IPSet()
	if err != nil {
		t.Fatal(err)
	}

	previousInterface := DefaultInterface.Load()
	previousFinder := DefaultInterfaceFinder.Load()
	previousExcludeSet := ProxyEndpointRouteExcludeSet.Load()
	DefaultInterface.Store("")
	DefaultInterfaceFinder.Store(interfaceFinderFunc(func(netip.Addr) string { return "auto" }))
	ProxyEndpointRouteExcludeSet.Store(excludeSet)
	t.Cleanup(func() {
		DefaultInterface.Store(previousInterface)
		DefaultInterfaceFinder.Store(previousFinder)
		ProxyEndpointRouteExcludeSet.Store(previousExcludeSet)
	})

	proxyEndpointDialer := applyOptions(WithProxyEndpointRouteExclude())
	if got := proxyEndpointDialer.selectExitInterface(endpoint); got != "" {
		t.Fatalf("excluded proxy endpoint selected interface %q, want system route", got)
	}
	if got := proxyEndpointDialer.selectExitInterface(netip.MustParseAddr("1.1.1.1")); got != "auto" {
		t.Fatalf("non-excluded proxy endpoint selected interface %q, want automatic interface", got)
	}
}

func TestProxyEndpointRouteExcludeRespectsGlobalInterface(t *testing.T) {
	endpoint := netip.MustParseAddr("100.64.0.1")
	excludeBuilder := netipx.IPSetBuilder{}
	excludeBuilder.AddPrefix(netip.MustParsePrefix("100.64.0.0/10"))
	excludeSet, err := excludeBuilder.IPSet()
	if err != nil {
		t.Fatal(err)
	}

	previousInterface := DefaultInterface.Load()
	previousFinder := DefaultInterfaceFinder.Load()
	previousExcludeSet := ProxyEndpointRouteExcludeSet.Load()
	DefaultInterface.Store("global")
	DefaultInterfaceFinder.Store(interfaceFinderFunc(func(netip.Addr) string { return "auto" }))
	ProxyEndpointRouteExcludeSet.Store(excludeSet)
	t.Cleanup(func() {
		DefaultInterface.Store(previousInterface)
		DefaultInterfaceFinder.Store(previousFinder)
		ProxyEndpointRouteExcludeSet.Store(previousExcludeSet)
	})

	proxyEndpointDialer := applyOptions(WithProxyEndpointRouteExclude())
	if got := proxyEndpointDialer.selectExitInterface(endpoint); got != "global" {
		t.Fatalf("excluded endpoint selected interface %q, want global interface", got)
	}
}
