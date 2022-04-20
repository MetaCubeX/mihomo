package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/log"
	"net/netip"
	"runtime"
)

func GetAutoDetectInterface() (string, error) {
	if runtime.GOOS == "android" {
		return cmd.ExecCmd("sh -c ip route | awk 'NR==1{print $3}' | xargs echo -n")
	}
	return cmd.ExecCmd("bash -c ip route show | grep 'default via' | awk -F ' ' 'NR==1{print $5}' | xargs echo -n")
}

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, forceMTU int, autoRoute bool) error {
	var (
		interfaceName = dev.Name()
		ip            = addr.Masked().Addr().Next()
	)

	_, err := cmd.ExecCmd(fmt.Sprintf("ip addr add %s dev %s", ip.String(), interfaceName))
	if err != nil {
		return err
	}

	_, err = cmd.ExecCmd(fmt.Sprintf("ip link set %s up", interfaceName))
	if err != nil {
		return err
	}

	if autoRoute {
		err = configInterfaceRouting(interfaceName, addr)
	}
	return err
}

func configInterfaceRouting(interfaceName string, addr netip.Prefix) error {
	if runtime.GOOS == "android" {
		tableId := 1981801
		for _, route := range defaultRoutes {
			if _, err := cmd.ExecCmd(fmt.Sprintf("ip route add %s dev %s scope link table %d", route, interfaceName, tableId)); err != nil {
				return err
			}
		}
		_, err := cmd.ExecCmd(fmt.Sprintf("ip rule add lookup %d suppress_prefixlength 0 pref 5000", tableId))
		if err != nil {
			log.Warnln("%s", err)
		}
	} else {
		linkIP := addr.Masked().Addr().Next()
		for _, route := range defaultRoutes {
			if err := execRouterCmd("add", route, interfaceName, linkIP.String()); err != nil {
				return err
			}
		}
	}

	go DefaultInterfaceChangeMonitor()

	return nil
}

func execRouterCmd(action, route string, interfaceName string, linkIP string) error {
	cmdStr := fmt.Sprintf("ip route %s %s dev %s proto kernel scope link src %s", action, route, interfaceName, linkIP)

	_, err := cmd.ExecCmd(cmdStr)
	return err
}
