//go:build !android

package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/listener/tun/device"
	"net/netip"
)

func GetAutoDetectInterface() (string, error) {
	return cmd.ExecCmd("bash -c ip route show | grep 'default via' | awk -F ' ' 'NR==1{print $5}' | xargs echo -n")
}

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, forceMTU int, autoRoute bool) error {
	var (
		interfaceName = dev.Name()
		ip            = addr.Masked().Addr().Next()
	)

	if _, err := cmd.ExecCmd(fmt.Sprintf("ip addr add %s dev %s", ip.String(), interfaceName)); err != nil {
		return err
	}

	if _, err := cmd.ExecCmd(fmt.Sprintf("ip link set %s up", interfaceName)); err != nil {
		return err
	}

	if err := execRouterCmd("add", addr.Masked().String(), interfaceName, ip.String(), "main"); err != nil {
		return err
	}

	if autoRoute {
		_ = configInterfaceRouting(interfaceName, addr)
	}
	return nil
}

func configInterfaceRouting(interfaceName string, addr netip.Prefix) error {
	linkIP := addr.Masked().Addr().Next()

	for _, route := range defaultRoutes {
		if err := execRouterCmd("add", route, interfaceName, linkIP.String(), "main"); err != nil {
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
