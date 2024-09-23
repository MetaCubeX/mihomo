//go:build !go1.21

package inbound

import "net"

const multipathTCPAvailable = false

func setMultiPathTCP(listenConfig *net.ListenConfig, open bool) {
}

func getMultiPathTCP(listenConfig *net.ListenConfig) bool {
	return false
}
