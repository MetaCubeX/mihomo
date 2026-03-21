package resolver

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/log"
)

var (
	ip4PEnable bool
)

func GetIP4PEnable() bool {
	return ip4PEnable
}

func SetIP4PEnable(enableIP4PConvert bool) {
	ip4PEnable = enableIP4PConvert
}

// kanged from https://github.com/heiher/frp/blob/ip4p/client/ip4p.go

func LookupIP4P(addr netip.Addr, port string) (netip.Addr, string) {
	if ip4PEnable {
		ip := addr.AsSlice()
		if ip[0] == 0x20 && ip[1] == 0x01 &&
			ip[2] == 0x00 && ip[3] == 0x00 {
			addr = netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
			port = strconv.Itoa(int(ip[10])<<8 + int(ip[11]))
			log.Debugln("Convert IP4P address %s to %s", ip, net.JoinHostPort(addr.String(), port))
			return addr, port
		}
	}
	return addr, port
}
