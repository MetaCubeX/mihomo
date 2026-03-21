//go:build !linux

package dialer

import (
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/log"
)

var printMarkWarnOnce sync.Once

func printMarkWarn() {
	printMarkWarnOnce.Do(func() {
		log.Warnln("Routing mark on socket is not supported on current platform")
	})
}

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	printMarkWarn()
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, _ string) {
	printMarkWarn()
}
