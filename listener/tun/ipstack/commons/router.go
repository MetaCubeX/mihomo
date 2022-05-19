package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/log"
	"net"
	"sync"
	"time"
)

var (
	defaultRoutes = []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"}

	monitorDuration = 3 * time.Second
	monitorStarted  = false
	monitorStop     = make(chan struct{}, 2)
	monitorMux      sync.Mutex
)

func ipv4MaskString(bits int) string {
	m := net.CIDRMask(bits, 32)
	if len(m) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func StartDefaultInterfaceChangeMonitor() {
	go func() {
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
	}()
}

func StopDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if monitorStarted {
		monitorStop <- struct{}{}
		monitorStarted = false
	}
}

func WaitForTunClose(deviceName string) {
	t := time.NewTicker(600 * time.Millisecond)
	defer t.Stop()
	log.Debugln("[TUN] waiting for device close")
	for {
		<-t.C
		interfaces, err := net.Interfaces()
		if err != nil {
			break
		}

		found := false
		for i := len(interfaces) - 1; i > -1; i-- {
			if interfaces[i].Name == deviceName {
				found = true
				break
			}
		}

		if !found {
			break
		}
	}
}
