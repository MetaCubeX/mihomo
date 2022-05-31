//go:build !android

package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/vishvananda/netlink"
	"net"
	"net/netip"
)

func GetAutoDetectInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}

	for _, route := range routes {
		if route.Dst == nil {
			lk, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", err
			}

			if lk.Type() == "tuntap" {
				continue
			}

			return lk.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("interface not found")
}

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, forceMTU int, autoRoute bool) error {
	var (
		interfaceName = dev.Name()
		ip            = addr.Masked().Addr().Next()
	)

	metaLink, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	naddr, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return err
	}

	if err = netlink.AddrAdd(metaLink, naddr); err != nil && err.Error() != "file exists" {
		return err
	}

	if err = netlink.LinkSetUp(metaLink); err != nil {
		return err
	}

	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: metaLink.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Protocol:  2,
		Src:       ip.AsSlice(),
		Table:     254,
	}); err != nil && err.Error() != "file exists" {
		return err
	}

	if autoRoute {
		_ = configInterfaceRouting(metaLink.Attrs().Index, interfaceName, ip)
	}
	return nil
}

func configInterfaceRouting(index int, interfaceName string, ip netip.Addr) error {
	for _, route := range defaultRoutes {
		_, ipn, err := net.ParseCIDR(route)
		if err != nil {
			return err
		}

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: index,
			Scope:     netlink.SCOPE_LINK,
			Protocol:  2,
			Src:       ip.AsSlice(),
			Dst:       ipn,
			Table:     254,
		}); err != nil {
			return err
		}
	}

	return nil
}

func execRouterCmd(action, route, interfaceName, linkIP, table string) error {
	cmdStr := fmt.Sprintf("ip route %s %s dev %s proto kernel scope link src %s table %s", action, route, interfaceName, linkIP, table)

	_, err := cmd.ExecCmd(cmdStr)
	return err
}

func CleanupRule() {}
