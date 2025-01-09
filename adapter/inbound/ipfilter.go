package inbound

import (
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

var lanAllowedIPs []netip.Prefix
var lanDisAllowedIPs []netip.Prefix

func SetAllowedIPs(prefixes []netip.Prefix) {
	lanAllowedIPs = prefixes
}

func SetDisAllowedIPs(prefixes []netip.Prefix) {
	lanDisAllowedIPs = prefixes
}

func AllowedIPs() []netip.Prefix {
	return lanAllowedIPs
}

func DisAllowedIPs() []netip.Prefix {
	return lanDisAllowedIPs
}

func IsRemoteAddrDisAllowed(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	ipAddr := m.AddrPort().Addr()
	if ipAddr.IsValid() {
		return isAllowed(ipAddr) && !isDisAllowed(ipAddr)
	}
	return false
}

func isAllowed(addr netip.Addr) bool {
	return prefixesContains(lanAllowedIPs, addr)
}

func isDisAllowed(addr netip.Addr) bool {
	return prefixesContains(lanDisAllowedIPs, addr)
}
