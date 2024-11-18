package inbound

import (
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

var skipAuthPrefixes []netip.Prefix

func SetSkipAuthPrefixes(prefixes []netip.Prefix) {
	skipAuthPrefixes = prefixes
}

func SkipAuthPrefixes() []netip.Prefix {
	return skipAuthPrefixes
}

func SkipAuthRemoteAddr(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func SkipAuthRemoteAddress(addr string) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddress(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func skipAuth(addr netip.Addr) bool {
	return prefixesContains(skipAuthPrefixes, addr)
}
