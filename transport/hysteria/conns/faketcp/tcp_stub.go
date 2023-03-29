//go:build !linux || no_fake_tcp
// +build !linux no_fake_tcp

package faketcp

import (
	"errors"
	"net"
)

type TCPConn struct{ *net.UDPConn }

// Dial connects to the remote TCP port,
// and returns a single packet-oriented connection
func Dial(network, address string) (*TCPConn, error) {
	return nil, errors.New("faketcp is not supported on this platform")
}

func Listen(network, address string) (*TCPConn, error) {
	return nil, errors.New("faketcp is not supported on this platform")
}
