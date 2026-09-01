//go:build linux

package ebpf

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNetNSTopologyIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_EBPF_NETNS_INTEGRATION") != "1" {
		t.Skip("set MIHOMO_EBPF_NETNS_INTEGRATION=1 to create the isolated veth topology")
	}
	require.NoError(t, assertLinkMissing(HostVethName))

	topology, err := CreateNetNSTopology()
	require.NoError(t, err)
	require.NotNil(t, topology)
	t.Cleanup(func() { require.NoError(t, topology.Close()) })

	_, err = netlink.LinkByName(HostVethName)
	require.NoError(t, err)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		require.True(t, hasRoutingRule(t, family))
		require.True(t, hasLocalRoute(t, family))
	}
	require.NoError(t, topology.Close())
	require.NoError(t, topology.Close())
	require.NoError(t, assertLinkMissing(HostVethName))
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		require.False(t, hasRoutingRule(t, family))
		require.False(t, hasLocalRoute(t, family))
	}
}

func assertLinkMissing(name string) error {
	_, err := netlink.LinkByName(name)
	if err == nil {
		return errors.New("link still exists")
	}
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	return err
}

func hasRoutingRule(t *testing.T, family int) bool {
	t.Helper()
	rules, err := netlink.RuleList(family)
	require.NoError(t, err)
	for _, rule := range rules {
		if rule.Table == RoutingTable && rule.Priority == routingRule(family).Priority && rule.Mark == TPROXYMark {
			return true
		}
	}
	return false
}

func hasLocalRoute(t *testing.T, family int) bool {
	t.Helper()
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: RoutingTable}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	for _, route := range routes {
		if route.Type == unix.RTN_LOCAL && route.Dst != nil && route.Dst.Mask.String() == "00000000" {
			return true
		}
		if family == unix.AF_INET6 && route.Type == unix.RTN_LOCAL && route.Dst != nil && route.Dst.Mask.String() == "00000000000000000000000000000000" {
			return true
		}
	}
	return false
}
