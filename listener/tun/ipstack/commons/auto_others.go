//go:build !linux

package commons

import (
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/log"
	"go.uber.org/atomic"
	"time"
)

var (
	monitorDuration = 3 * time.Second
	monitorStarted  = atomic.NewBool(false)
	monitorStop     = make(chan struct{}, 2)
)

func StartDefaultInterfaceChangeMonitor() {
	go func() {
		if monitorStarted.Load() {
			return
		}
		monitorStarted.Store(true)
		t := time.NewTicker(monitorDuration)
		log.Debugln("[TUN] start auto detect interface monitor")
		defer func() {
			monitorStarted.Store(false)
			t.Stop()
			log.Debugln("[TUN] stop auto detect interface monitor")
		}()

		select {
		case <-monitorStop:
		default:
		}

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
	if monitorStarted.Load() {
		monitorStop <- struct{}{}
	}
}
