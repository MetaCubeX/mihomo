// +build !linux

package redir

import (
	"errors"
	"net"
)

func dialUDP(network string, lAddr *net.UDPAddr, rAddr *net.UDPAddr) (*net.UDPConn, error) {
	return nil, errors.New("UDP redir not supported on current platform")
}
