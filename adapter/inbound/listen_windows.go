package inbound

import (
	"net"
)

var (
	lc = net.ListenConfig{}
)

func SetTfo(open bool) {}

func getListenConfig() *net.ListenConfig {
	return &lc
}
