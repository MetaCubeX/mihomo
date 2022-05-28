package commons

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/log"
)

func GetAutoDetectInterface() (string, error) {
	return cmd.ExecCmd("bash -c ip route show | grep 'default via' | awk -F ' ' 'NR==1{print $5}' | xargs echo -n")
}

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, _ int, autoRoute bool) error {
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
	linkIP := addr.Masked().Addr().Next()
	for _, route := range defaultRoutes {
		if err := execRouterCmd("add", route, interfaceName, linkIP.String()); err != nil {
			return err
		}
	}

	return nil
}

func execRouterCmd(action, route string, interfaceName string, linkIP string) error {
	cmdStr := fmt.Sprintf("ip route %s %s dev %s proto kernel scope link src %s", action, route, interfaceName, linkIP)

	_, err := cmd.ExecCmd(cmdStr)
	return err
}

func StartDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	if monitorStarted {
		monitorMux.Unlock()
		return
	}
	monitorStarted = true
	monitorMux.Unlock()

	select {
	case <-monitorStop:
	default:
	}

	t := time.NewTicker(monitorDuration)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			interfaceName, err := GetAutoDetectInterface()
			if err != nil {
				log.Warnln("[TUN] default interface monitor err: %v", err)
				continue
			}

			old := dialer.DefaultInterface.Load()
			if interfaceName == old {
				continue
			}

			dialer.DefaultInterface.Store(interfaceName)

			iface.FlushCache()

			log.Warnln("[TUN] default interface changed by monitor, %s => %s", old, interfaceName)
		case <-monitorStop:
			break
		}
	}
}

func StopDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if monitorStarted {
		monitorStop <- struct{}{}
		monitorStarted = false
	}
}
