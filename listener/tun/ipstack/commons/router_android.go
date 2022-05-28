package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/log"
	"github.com/vishvananda/netlink"
	"net"
	"net/netip"
	"strings"
)

func GetAutoDetectInterface() (ifn string, err error) {
	cmdRes, err := cmd.ExecCmd("ip route get 1.1.1.1 uid 4294967295")

	sps := strings.Split(cmdRes, " ")
	if len(sps) > 4 {
		ifn = sps[4]
	}

	if ifn == "" {
		err = fmt.Errorf("interface not found")
	}
	return
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

	if err = netlink.AddrAdd(metaLink, naddr); err != nil {
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
	}); err != nil {
		return err
	}

	if autoRoute {
		err = configInterfaceRouting(metaLink.Attrs().Index, interfaceName, ip)
	}
	return err
}

func configInterfaceRouting(index int, interfaceName string, ip netip.Addr) error {
	const tableId = 1981801

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
	execAddRuleCmd(fmt.Sprintf("lookup main pref 9000"))
	execAddRuleCmd(fmt.Sprintf("from 0.0.0.0 iif lo uidrange 0-4294967294 lookup %d pref 9001", tableId))
	execAddRuleCmd(fmt.Sprintf("from %s iif lo uidrange 0-4294967294 lookup %d pref 9002", ip, tableId))
	execAddRuleCmd(fmt.Sprintf("from all iif %s lookup main suppress_prefixlength 0 pref 9003", interfaceName))
	execAddRuleCmd(fmt.Sprintf("not from all iif lo lookup %d pref 9004", tableId))

	return nil
}

func execAddRuleCmd(rule string) {
	_, err := cmd.ExecCmd("ip rule add " + rule)
	if err != nil {
		log.Warnln("%s", err)
	}
}

func execRouterCmd(action, route, interfaceName, linkIP, table string) error {
	cmdStr := fmt.Sprintf("ip route %s %s dev %s proto kernel scope link src %s table %s", action, route, interfaceName, linkIP, table)

	_, err := cmd.ExecCmd(cmdStr)
	return err
}
