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

func IsRemoteAddrAllowed(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	return isAllowed(m.AddrPort().Addr()) && !isDisAllowed(m.AddrPort().Addr())
}

func IsRemoteAddressAllowed(addr string) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddress(addr); err != nil {
		return false
	}
	return isAllowed(m.AddrPort().Addr()) && !isDisAllowed(m.AddrPort().Addr())
}

func isAllowed(addr netip.Addr) bool {
	if addr.IsValid() {
		for _, prefix := range lanAllowedIPs {
			if prefix.Contains(addr.Unmap()) {
				return true
			}
		}
	}
	return false
}

func isDisAllowed(addr netip.Addr) bool {
	if addr.IsValid() {
		for _, prefix := range lanDisAllowedIPs {
			if prefix.Contains(addr.Unmap()) {
				return true
			}
		}
	}
	return false
}
