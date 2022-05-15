package commons

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/listener/tun/device"
)

func GetAutoDetectInterface() (string, error) {
	rs, err := cmd.ExecCmd("/bin/bash -c /sbin/route -n get default | grep 'interface:' | awk -F ' ' 'NR==1{print $2}' | xargs echo -n")
	if err != nil {
		return "", err
	}

	if rs == "" || strings.HasSuffix(rs, "\n") {
		return "", fmt.Errorf("invalid interface name: %s", rs)
	}

	return rs, nil
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
