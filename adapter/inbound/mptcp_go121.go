//go:build go1.21

package inbound

import "net"

const multipathTCPAvailable = true

func setMultiPathTCP(listenConfig *net.ListenConfig, open bool) {
	listenConfig.SetMultipathTCP(open)
}

func getMultiPathTCP(listenConfig *net.ListenConfig) bool {
	return listenConfig.MultipathTCP()
}
