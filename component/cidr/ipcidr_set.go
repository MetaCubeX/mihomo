package cidr

import (
	"go4.org/netipx"
	"net/netip"
)

type IpCidrSet struct {
	Ranges *netipx.IPSet
}

func NewIpCidrSet() *IpCidrSet {
	return &IpCidrSet{}
}

func (set *IpCidrSet) AddIpCidrForString(ipCidr string) error {
	prefix, err := netip.ParsePrefix(ipCidr)
	if err != nil {
		return err
	}
	err = set.AddIpCidr(prefix)
	return nil
}

func (set *IpCidrSet) AddIpCidr(ipCidr netip.Prefix) (err error) {
	var b netipx.IPSetBuilder
	b.AddSet(set.Ranges)
	b.AddPrefix(ipCidr)
	set.Ranges, err = b.IPSet()
	return
}

func (set *IpCidrSet) IsContainForString(ipString string) bool {
	ip, err := netip.ParseAddr(ipString)
	if err != nil {
		return false
	}
	return set.IsContain(ip)
}

func (set *IpCidrSet) IsContain(ip netip.Addr) bool {
	if set.Ranges == nil {
		return false
	}
	return set.Ranges.Contains(ip.WithZone(""))
}

func (set *IpCidrSet) Merge() {}
