package net

import (
	"net"
)

type CustomAddr interface {
	net.Addr
	RawAddr() net.Addr
}

type customAddr struct {
	networkStr string
	addrStr    string
	rawAddr    net.Addr
}

func (a customAddr) Network() string {
	return a.networkStr
}

func (a customAddr) String() string {
	return a.addrStr
}

func (a customAddr) RawAddr() net.Addr {
	return a.rawAddr
}

func NewCustomAddr(networkStr string, addrStr string, rawAddr net.Addr) CustomAddr {
	return customAddr{
		networkStr: networkStr,
		addrStr:    addrStr,
		rawAddr:    rawAddr,
	}
}
