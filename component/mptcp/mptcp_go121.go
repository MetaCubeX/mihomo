//go:build go1.21

package mptcp

import "net"

const MultipathTCPAvailable = true

func SetNetDialer(dialer *net.Dialer, open bool) {
	dialer.SetMultipathTCP(open)
}

func GetNetDialer(dialer *net.Dialer) bool {
	return dialer.MultipathTCP()
}

func SetNetListenConfig(listenConfig *net.ListenConfig, open bool) {
	listenConfig.SetMultipathTCP(open)
}

func GetNetListenConfig(listenConfig *net.ListenConfig) bool {
	return listenConfig.MultipathTCP()
}
