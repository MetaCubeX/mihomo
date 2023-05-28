package net

import (
	"net"

	"github.com/Dreamacro/clash/log"

	M "github.com/sagernet/sing/common/metadata"
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

func CopyUDPAddr(netAddr net.Addr) *net.UDPAddr {
	switch addr := netAddr.(type) {
	case M.Socksaddr:
		return addr.UDPAddr()
	case *net.UDPAddr:
		_addr := *addr
		return &_addr // make a copy
	default:
		log.Fatalln("Unknown UDP address type: %T", addr)
		return nil // unreachable
	}
}
