package inbound

import (
	"net"
	"net/netip"
)

var skipAuthPrefixes []netip.Prefix

func SetSkipAuthPrefixes(prefixes []netip.Prefix) {
	skipAuthPrefixes = prefixes
}

func SkipAuthPrefixes() []netip.Prefix {
	return skipAuthPrefixes
}

func SkipAuthRemoteAddr(addr net.Addr) bool {
	if addrPort := parseAddr(addr); addrPort.IsValid() {
		for _, prefix := range skipAuthPrefixes {
			if prefix.Contains(addrPort.Addr().Unmap()) {
				return true
			}
		}
	}
	return false
}
