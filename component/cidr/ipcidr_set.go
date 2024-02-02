package cidr

import (
	"fmt"
	"net/netip"
	"unsafe"

	"go4.org/netipx"
)

type IpCidrSet struct {
	// must same with netipx.IPSet
	rr []netipx.IPRange
}

func NewIpCidrSet() *IpCidrSet {
	return &IpCidrSet{}
}

func (set *IpCidrSet) AddIpCidrForString(ipCidr string) error {
	prefix, err := netip.ParsePrefix(ipCidr)
	if err != nil {
		return err
	}
	return set.AddIpCidr(prefix)
}

func (set *IpCidrSet) AddIpCidr(ipCidr netip.Prefix) (err error) {
	if r := netipx.RangeOfPrefix(ipCidr); r.IsValid() {
		set.rr = append(set.rr, r)
	} else {
		err = fmt.Errorf("not valid ipcidr range: %s", ipCidr)
	}
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
	return set.toIPSet().Contains(ip.WithZone(""))
}

func (set *IpCidrSet) Merge() error {
	var b netipx.IPSetBuilder
	b.AddSet(set.toIPSet())
	i, err := b.IPSet()
	if err != nil {
		return err
	}
	set.fromIPSet(i)
	return nil
}

func (set *IpCidrSet) toIPSet() *netipx.IPSet {
	return (*netipx.IPSet)(unsafe.Pointer(set))
}

func (set *IpCidrSet) fromIPSet(i *netipx.IPSet) {
	*set = *(*IpCidrSet)(unsafe.Pointer(i))
}
