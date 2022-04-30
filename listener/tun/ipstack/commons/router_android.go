package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/log"
	"net/netip"
	"strconv"
	"strings"
)

func GetAutoDetectInterface() (string, error) {
	res, err := cmd.ExecCmd("sh -c ip route | awk '{print $3}' | xargs echo -n")
	if err != nil {
		return "", err
	}
	ifaces := strings.Split(res, " ")
	for _, iface := range ifaces {
		if iface == "wlan0" {
			return "wlan0", nil
		}
	}
	return ifaces[0], nil
}

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, forceMTU int, autoRoute, autoDetectInterface bool) error {
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
		err = configInterfaceRouting(interfaceName, addr, autoDetectInterface)
	}
	return err
}

func configInterfaceRouting(interfaceName string, addr netip.Prefix, autoDetectInterface bool) error {
	linkIP := addr.Masked().Addr().Next()
	const tableId = 1981801

	for _, route := range defaultRoutes {
		if err := execRouterCmd("add", route, interfaceName, linkIP.String(), strconv.Itoa(tableId)); err != nil {
			return err
		}
	}
	execAddRuleCmd(fmt.Sprintf("lookup main pref 9000"))
	execAddRuleCmd(fmt.Sprintf("from 0.0.0.0 iif lo uidrange 0-4294967294 lookup %d pref 9001", tableId))
	execAddRuleCmd(fmt.Sprintf("from %s iif lo uidrange 0-4294967294 lookup %d pref 9002", linkIP, tableId))
	execAddRuleCmd(fmt.Sprintf("from all iif %s lookup main suppress_prefixlength 0 pref 9003", interfaceName))
	execAddRuleCmd(fmt.Sprintf("not from all iif lo lookup %d pref 9004", tableId))

	if autoDetectInterface {
		go DefaultInterfaceChangeMonitor()
	}

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
