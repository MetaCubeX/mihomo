package sing_tun

import (
	"fmt"
	"os"
	"strconv"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
)

func (l *Listener) startInterfaceMonitor(name string) error {
	monitor, err := tun.NewNetworkUpdateMonitor(log.SingLogger)
	if err != nil {
		return fmt.Errorf("create NetworkUpdateMonitor: %w", err)
	}
	l.networkUpdateMonitor = monitor
	if err = monitor.Start(); err != nil {
		return fmt.Errorf("start NetworkUpdateMonitor: %w", err)
	}
	disable, _ := strconv.ParseBool(os.Getenv("DISABLE_OVERRIDE_ANDROID_VPN"))
	defaultMonitor, err := tun.NewDefaultInterfaceMonitor(monitor, log.SingLogger, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: DefaultInterfaceFinder, OverrideAndroidVPN: !disable})
	if err != nil {
		return fmt.Errorf("create DefaultInterfaceMonitor: %w", err)
	}
	l.defaultInterfaceMonitor = defaultMonitor
	defaultMonitor.RegisterCallback(func(defaultInterface *control.Interface, event int) {
		if defaultInterface != nil {
			log.Warnln("[TUN] default interface changed by monitor, => %s", defaultInterface.Name)
		} else {
			log.Errorln("[TUN] default interface lost by monitor")
		}
		iface.FlushCache()
		resolver.ResetConnection()
	})
	if err = defaultMonitor.Start(); err != nil {
		return fmt.Errorf("start DefaultInterfaceMonitor: %w", err)
	}
	if l.options.AutoDetectInterface {
		l.cDialerInterfaceFinder = &cDialerInterfaceFinder{tunName: name, defaultInterfaceMonitor: defaultMonitor}
		if !dialer.DefaultInterfaceFinder.CompareAndSwap(nil, l.cDialerInterfaceFinder) {
			return fmt.Errorf("not allowed two tun listener using auto-detect-interface")
		}
	}
	return nil
}
