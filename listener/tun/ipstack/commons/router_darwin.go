package commons

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/listener/tun/device"

	"golang.org/x/net/route"
)

func GetAutoDetectInterface() (string, error) {
	iface, err := defaultRouteInterface()
	if err != nil {
		return "", err
	}
	return iface.Name, nil
}

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, forceMTU int, autoRoute bool) error {
	if !addr.Addr().Is4() {
		return fmt.Errorf("supported ipv4 only")
	}

	var (
		interfaceName = dev.Name()
		ip            = addr.Masked().Addr().Next()
		gw            = ip.Next()
		netmask       = ipv4MaskString(addr.Bits())
	)

	cmdStr := fmt.Sprintf("/sbin/ifconfig %s inet %s netmask %s %s", interfaceName, ip, netmask, gw)

	_, err := cmd.ExecCmd(cmdStr)
	if err != nil {
		return err
	}

	_, err = cmd.ExecCmd(fmt.Sprintf("/usr/sbin/ipconfig set %s automatic-v6", interfaceName))
	if err != nil {
		return err
	}

	if autoRoute {
		err = configInterfaceRouting(interfaceName, addr)
	}
	return err
}

func configInterfaceRouting(interfaceName string, addr netip.Prefix) error {
	var (
		routes  = append(defaultRoutes, addr.String())
		gateway = addr.Masked().Addr().Next()
	)

	for _, destination := range routes {
		if _, err := cmd.ExecCmd(fmt.Sprintf("/sbin/route add -net %s %s", destination, gateway)); err != nil {
			return err
		}
	}

	return execRouterCmd("add", "-inet6", "2000::/3", interfaceName)
}

func execRouterCmd(action, inet, route string, interfaceName string) error {
	_, err := cmd.ExecCmd(fmt.Sprintf("/sbin/route %s %s %s -interface %s", action, inet, route, interfaceName))
	return err
}

func defaultRouteInterface() (*net.Interface, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, syscall.NET_RT_DUMP2, 0)
	if err != nil {
		return nil, fmt.Errorf("route.FetchRIB: %w", err)
	}

	msgs, err := route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
	if err != nil {
		return nil, fmt.Errorf("route.ParseRIB: %w", err)
	}

	for _, message := range msgs {
		routeMessage := message.(*route.RouteMessage)
		if routeMessage.Flags&(syscall.RTF_UP|syscall.RTF_GATEWAY|syscall.RTF_STATIC) == 0 {
			continue
		}

		addresses := routeMessage.Addrs

		if (addresses[0].Family() == syscall.AF_INET && addresses[0].(*route.Inet4Addr).IP != *(*[4]byte)(net.IPv4zero)) ||
			(addresses[0].Family() == syscall.AF_INET6 && addresses[0].(*route.Inet6Addr).IP != *(*[16]byte)(net.IPv6zero)) {

			continue
		}

		iface, err1 := net.InterfaceByIndex(routeMessage.Index)
		if err1 != nil {
			continue
		}

		if strings.HasPrefix(iface.Name, "utun") {
			continue
		}

		return iface, nil
	}

	return nil, fmt.Errorf("ambiguous gateway interfaces found")
}
