//go:build unix

package inbound

import (
	"net"

	"github.com/metacubex/tfo-go"
)

var (
	lc = tfo.ListenConfig{
		DisableTFO: true,
	}
)

func SetTfo(open bool) {
	lc.DisableTFO = !open
}

func getListenConfig() *net.ListenConfig {
	return &lc.ListenConfig
}
