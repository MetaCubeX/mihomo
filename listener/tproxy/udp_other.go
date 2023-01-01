//go:build !linux

package tproxy

import (
	"errors"
	"net"
	"net/netip"
)

func getOrigDst(oob []byte) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("UDP redir not supported on current platform")
}

func dialUDP(network string, lAddr, rAddr netip.AddrPort) (*net.UDPConn, error) {
	return nil, errors.New("UDP redir not supported on current platform")
}
