package constant

import "net/netip"

type DomainMatcher interface {
	MatchDomain(domain string) bool
}

type IpMatcher interface {
	MatchIp(ip netip.Addr) bool
}
