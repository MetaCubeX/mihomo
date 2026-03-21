//go:build !go1.21

package mptcp

import (
	"net"
)

const MultipathTCPAvailable = false

func SetNetDialer(dialer *net.Dialer, open bool) {
}

func GetNetDialer(dialer *net.Dialer) bool {
	return false
}

func SetNetListenConfig(listenConfig *net.ListenConfig, open bool) {
}

func GetNetListenConfig(listenConfig *net.ListenConfig) bool {
	return false
}
