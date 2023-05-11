//go:build windows

package net

import (
	"net"
)

type enhanceUDPConn struct {
	*net.UDPConn
}

func (c *enhanceUDPConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	return waitReadFrom(c.UDPConn)
}
