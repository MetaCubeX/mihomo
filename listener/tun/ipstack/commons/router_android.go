package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/log"
	"github.com/vishvananda/netlink"
	"net"
	"net/netip"
)

func GetAutoDetectInterface() (ifn string, err error) {
	routes, err := netlink.RouteGetWithOptions(
		net.ParseIP("1.1.1.1"),
		&netlink.RouteGetOptions{
			Uid: &netlink.UID{Uid: 4294967295},
		})
	if err != nil {
		return "", err
	}

	for _, route := range routes {
		if lk, err := netlink.LinkByIndex(route.LinkIndex); err == nil {
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

	if autoRoute {
		err = configInterfaceRouting(metaLink.Attrs().Index, interfaceName, ip)
	}
	return err
}

func configInterfaceRouting(index int, interfaceName string, ip netip.Addr) error {
	const tableId = 1981801
	var pref = 9000

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
			Table:     tableId,
		}); err != nil {
			return err
		}
	}

	logIfErr := func(e error) {
		if e != nil {
			log.Warnln("[TOUTE] config route rule: %s", e)
		}
	}

	var r *netlink.Rule
	r = netlink.NewRule()
	r.Table = 254
	r.Priority = pref
	logIfErr(netlink.RuleAdd(r))
	pref += 10

	r = netlink.NewRule()
	_, nl, _ := net.ParseCIDR("0.0.0.0/32")
	r.Table = tableId
	r.Priority = pref
	r.Src = nl
	r.IifName = "lo"
	r.UID = netlink.NewRuleUIDRange(0, 4294967294)
	logIfErr(netlink.RuleAdd(r))
	pref += 10

	_, nl, _ = net.ParseCIDR(ip.String())
	r.Priority = pref
	r.Src = nl
	logIfErr(netlink.RuleAdd(r))
	pref += 10

	r = netlink.NewRule()
	r.Table = 254
	r.Priority = pref
	r.IifName = interfaceName
	r.SuppressPrefixlen = 0
	logIfErr(netlink.RuleAdd(r))
	pref += 10

	r = netlink.NewRule()
	r.Table = tableId
	r.Priority = pref
	r.IifName = "lo"
	r.SuppressPrefixlen = 0
	r.Invert = true
	logIfErr(netlink.RuleAdd(r))

	return nil
}

func CleanupRule() {
	r := netlink.NewRule()
	for i := 0; i < 5; i++ {
		r.Priority = 9000 + i*10
		err := netlink.RuleDel(r)
		if err != nil {
			log.Warnln("[TOUTE] cleanup route rule: %s", err)
		}
	}
}
