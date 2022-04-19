package commons

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/log"
)

var (
	defaultRoutes                   = []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"}
	mux                             sync.Mutex
	defaultInterfaceMonitorDuration = 3 * time.Second
)

func ipv4MaskString(bits int) string {
	m := net.CIDRMask(bits, 32)
	if len(m) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func DefaultInterfaceChangeMonitor(cb func(ifName string)) {
	t := time.NewTicker(defaultInterfaceMonitorDuration)
	defer t.Stop()

	for {
		<-t.C

		interfaceName, err := GetAutoDetectInterface()
		if err != nil {
			log.Warnln("[TUN] default interface monitor exited, cause: %v", err)
			break
		}

		old := dialer.DefaultInterface.Load()
		if interfaceName == old {
			continue
		}

		dialer.DefaultInterface.Store(interfaceName)
		if cb != nil {
			cb(interfaceName)
		}
		log.Warnln("[TUN] default interface changed by monitor, %s => %s", old, interfaceName)
	}
}
