package commons

import (
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/log"
	"github.com/vishvananda/netlink"
	"go.uber.org/atomic"
	"time"
)

var (
	monitorStarted = atomic.NewBool(false)
	monitorStop    = make(chan struct{}, 2)
)

func StartDefaultInterfaceChangeMonitor() {
	go func() {
		if monitorStarted.Load() {
			return
		}
		monitorStarted.Store(true)

		done := make(chan struct{})
		ch := make(chan netlink.RouteUpdate, 2)
		err := netlink.RouteSubscribe(ch, done)
		if err != nil {
			log.Warnln("[TUN] auto detect interface fail: %s", err)
			return
		}
		log.Debugln("[TUN] start auto detect interface monitor")
		defer func() {
			close(done)
			monitorStarted.Store(false)
			log.Debugln("[TUN] stop auto detect interface monitor")
		}()

		select {
		case <-monitorStop:
		default:
		}

		for {
			select {
			case <-monitorStop:
				return
			case <-ch:
			}

			interfaceName, err := GetAutoDetectInterface()
			if err != nil {
				t := time.NewTicker(2 * time.Second)
				for {
					select {
					case ch <- <-ch:
						break
					case <-t.C:
						interfaceName, err = GetAutoDetectInterface()
						if err != nil {
							continue
						}
					}
					break
				}
				t.Stop()
			}

			if err != nil {
				log.Debugln("[TUN] detect interface: %s", err)
				continue
			}

			old := dialer.DefaultInterface.Load()
			if interfaceName == old {
				continue
			}

			dialer.DefaultInterface.Store(interfaceName)
			iface.FlushCache()

			log.Warnln("[TUN] default interface changed by monitor, %s => %s", old, interfaceName)
		}
	}()
}

func StopDefaultInterfaceChangeMonitor() {
	if monitorStarted.Load() {
		monitorStop <- struct{}{}
	}
}
