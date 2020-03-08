// +build !linux

package redir

import (
	"errors"
	"net"
)

func setsockopt(c *net.UDPConn, addr string) error {
	return errors.New("UDP redir not supported on current platform")
}

func getOrigDst(oob []byte, oobn int) (*net.UDPAddr, error) {
	return nil, errors.New("UDP redir not supported on current platform")
}
