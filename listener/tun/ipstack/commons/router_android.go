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

	_, err := cmd.ExecCmd(fmt.Sprintf("ip addr add %s dev %s", ip.String(), interfaceName))
	if err != nil {
		return err
	}

	_, err = cmd.ExecCmd(fmt.Sprintf("ip link set %s up", interfaceName))
	if err != nil {
		return err
	}

	if err = execRouterCmd("add", addr.Masked().String(), interfaceName, ip.String(), "main"); err != nil {
		return err
	}

	if autoRoute {
		err = configInterfaceRouting(interfaceName, addr)
	}
	return err
}

func configInterfaceRouting(interfaceName string, addr netip.Prefix) error {
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
