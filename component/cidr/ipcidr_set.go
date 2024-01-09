package cidr

import (
	"math/big"
	"net"
	"sort"
)

type Range struct {
	Start *big.Int
	End   *big.Int
}

type IpCidrSet struct {
	Ranges []Range
}

func NewIpCidrSet() *IpCidrSet {
	return &IpCidrSet{}
}

func ipToBigInt(ip net.IP) *big.Int {
	ipBigInt := big.NewInt(0)
	ipBigInt.SetBytes(ip.To16())
	return ipBigInt
}

func cidrToRange(cidr string) (Range, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return Range{}, err
	}
	firstIP, lastIP := networkRange(ipNet)
	return Range{Start: ipToBigInt(firstIP), End: ipToBigInt(lastIP)}, nil
}

func networkRange(network *net.IPNet) (net.IP, net.IP) {
	firstIP := network.IP
	lastIP := make(net.IP, len(firstIP))
	copy(lastIP, firstIP)
	for i := range firstIP {
		lastIP[i] |= ^network.Mask[i]
	}
	return firstIP, lastIP
}

func (set *IpCidrSet) AddIpCidrForString(ipCidr string) error {
	ipRange, err := cidrToRange(ipCidr)
	if err != nil {
		return err
	}
	set.Ranges = append(set.Ranges, ipRange)
	sort.Slice(set.Ranges, func(i, j int) bool {
		return set.Ranges[i].Start.Cmp(set.Ranges[j].Start) < 0
	})
	return nil
}

func (set *IpCidrSet) AddIpCidr(ipCidr *net.IPNet) error {
	return set.AddIpCidrForString(ipCidr.String())
}

func (set *IpCidrSet) IsContainForString(ipString string) bool {
	ip := ipToBigInt(net.ParseIP(ipString))
	idx := sort.Search(len(set.Ranges), func(i int) bool {
		return set.Ranges[i].End.Cmp(ip) >= 0
	})
	if idx < len(set.Ranges) && set.Ranges[idx].Start.Cmp(ip) <= 0 && set.Ranges[idx].End.Cmp(ip) >= 0 {
		return true
	}
	return false
}

func (set *IpCidrSet) IsContain(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return set.IsContainForString(ip.String())
}

func (set *IpCidrSet) Merge() {
	for i := 0; i < len(set.Ranges)-1; i++ {
		if set.Ranges[i].End.Cmp(set.Ranges[i+1].Start) >= 0 {
			set.Ranges[i].End = set.Ranges[i+1].End
			set.Ranges = append(set.Ranges[:i+1], set.Ranges[i+2:]...)
			i--
		}
	}
}
