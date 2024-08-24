package config

import (
	"net/netip"

	"github.com/metacubex/mihomo/common/nnip"
	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/exp/slices"
)

func StringSliceToNetipPrefixSlice(ss []string) ([]netip.Prefix, error) {
	lps := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		lps = append(lps, prefix)
	}
	return lps, nil
}

type Tun struct {
	Enable              bool       `yaml:"enable" json:"enable"`
	Device              string     `yaml:"device" json:"device"`
	Stack               C.TUNStack `yaml:"stack" json:"stack"`
	DNSHijack           []string   `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool       `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool       `yaml:"auto-detect-interface" json:"auto-detect-interface"`

	MTU                    uint32         `yaml:"mtu" json:"mtu,omitempty"`
	GSO                    bool           `yaml:"gso" json:"gso,omitempty"`
	GSOMaxSize             uint32         `yaml:"gso-max-size" json:"gso-max-size,omitempty"`
	Inet4Address           []netip.Prefix `yaml:"inet4-address" json:"inet4-address,omitempty"`
	Inet6Address           []netip.Prefix `yaml:"inet6-address" json:"inet6-address,omitempty"`
	IPRoute2TableIndex     int            `yaml:"iproute2-table-index" json:"iproute2-table-index,omitempty"`
	IPRoute2RuleIndex      int            `yaml:"iproute2-rule-index" json:"iproute2-rule-index,omitempty"`
	AutoRedirect           bool           `yaml:"auto-redirect" json:"auto-redirect,omitempty"`
	AutoRedirectInputMark  uint32         `yaml:"auto-redirect-input-mark" json:"auto-redirect-input-mark,omitempty"`
	AutoRedirectOutputMark uint32         `yaml:"auto-redirect-output-mark" json:"auto-redirect-output-mark,omitempty"`
	StrictRoute            bool           `yaml:"strict-route" json:"strict-route,omitempty"`
	RouteAddress           []netip.Prefix `yaml:"route-address" json:"route-address,omitempty"`
	RouteAddressSet        []string       `yaml:"route-address-set" json:"route-address-set,omitempty"`
	RouteExcludeAddress    []netip.Prefix `yaml:"route-exclude-address" json:"route-exclude-address,omitempty"`
	RouteExcludeAddressSet []string       `yaml:"route-exclude-address-set" json:"route-exclude-address-set,omitempty"`
	IncludeInterface       []string       `yaml:"include-interface" json:"include-interface,omitempty"`
	ExcludeInterface       []string       `yaml:"exclude-interface" json:"exclude-interface,omitempty"`
	IncludeUID             []uint32       `yaml:"include-uid" json:"include-uid,omitempty"`
	IncludeUIDRange        []string       `yaml:"include-uid-range" json:"include-uid-range,omitempty"`
	ExcludeUID             []uint32       `yaml:"exclude-uid" json:"exclude-uid,omitempty"`
	ExcludeUIDRange        []string       `yaml:"exclude-uid-range" json:"exclude-uid-range,omitempty"`
	IncludeAndroidUser     []int          `yaml:"include-android-user" json:"include-android-user,omitempty"`
	IncludePackage         []string       `yaml:"include-package" json:"include-package,omitempty"`
	ExcludePackage         []string       `yaml:"exclude-package" json:"exclude-package,omitempty"`
	EndpointIndependentNat bool           `yaml:"endpoint-independent-nat" json:"endpoint-independent-nat,omitempty"`
	UDPTimeout             int64          `yaml:"udp-timeout" json:"udp-timeout,omitempty"`
	FileDescriptor         int            `yaml:"file-descriptor" json:"file-descriptor"`

	Inet4RouteAddress        []netip.Prefix `yaml:"inet4-route-address" json:"inet4-route-address,omitempty"`
	Inet6RouteAddress        []netip.Prefix `yaml:"inet6-route-address" json:"inet6-route-address,omitempty"`
	Inet4RouteExcludeAddress []netip.Prefix `yaml:"inet4-route-exclude-address" json:"inet4-route-exclude-address,omitempty"`
	Inet6RouteExcludeAddress []netip.Prefix `yaml:"inet6-route-exclude-address" json:"inet6-route-exclude-address,omitempty"`
}

func (t *Tun) Sort() {
	slices.Sort(t.DNSHijack)

	slices.SortFunc(t.Inet4Address, nnip.PrefixCompare)
	slices.SortFunc(t.Inet6Address, nnip.PrefixCompare)
	slices.SortFunc(t.RouteAddress, nnip.PrefixCompare)
	slices.Sort(t.RouteAddressSet)
	slices.SortFunc(t.RouteExcludeAddress, nnip.PrefixCompare)
	slices.Sort(t.RouteExcludeAddressSet)
	slices.Sort(t.IncludeInterface)
	slices.Sort(t.ExcludeInterface)
	slices.Sort(t.IncludeUID)
	slices.Sort(t.IncludeUIDRange)
	slices.Sort(t.ExcludeUID)
	slices.Sort(t.ExcludeUIDRange)
	slices.Sort(t.IncludeAndroidUser)
	slices.Sort(t.IncludePackage)
	slices.Sort(t.ExcludePackage)

	slices.SortFunc(t.Inet4RouteAddress, nnip.PrefixCompare)
	slices.SortFunc(t.Inet6RouteAddress, nnip.PrefixCompare)
	slices.SortFunc(t.Inet4RouteExcludeAddress, nnip.PrefixCompare)
	slices.SortFunc(t.Inet6RouteExcludeAddress, nnip.PrefixCompare)
}

func (t *Tun) Equal(other Tun) bool {
	if t.Enable != other.Enable {
		return false
	}
	if t.Device != other.Device {
		return false
	}
	if t.Stack != other.Stack {
		return false
	}
	if !slices.Equal(t.DNSHijack, other.DNSHijack) {
		return false
	}
	if t.AutoRoute != other.AutoRoute {
		return false
	}
	if t.AutoDetectInterface != other.AutoDetectInterface {
		return false
	}

	if t.MTU != other.MTU {
		return false
	}
	if t.GSO != other.GSO {
		return false
	}
	if t.GSOMaxSize != other.GSOMaxSize {
		return false
	}
	if !slices.Equal(t.Inet4Address, other.Inet4Address) {
		return false
	}
	if !slices.Equal(t.Inet6Address, other.Inet6Address) {
		return false
	}
	if t.IPRoute2TableIndex != other.IPRoute2TableIndex {
		return false
	}
	if t.IPRoute2RuleIndex != other.IPRoute2RuleIndex {
		return false
	}
	if t.AutoRedirect != other.AutoRedirect {
		return false
	}
	if t.AutoRedirectInputMark != other.AutoRedirectInputMark {
		return false
	}
	if t.AutoRedirectOutputMark != other.AutoRedirectOutputMark {
		return false
	}
	if t.StrictRoute != other.StrictRoute {
		return false
	}
	if !slices.Equal(t.RouteAddress, other.RouteAddress) {
		return false
	}
	if !slices.Equal(t.RouteAddressSet, other.RouteAddressSet) {
		return false
	}
	if !slices.Equal(t.RouteExcludeAddress, other.RouteExcludeAddress) {
		return false
	}
	if !slices.Equal(t.RouteExcludeAddressSet, other.RouteExcludeAddressSet) {
		return false
	}
	if !slices.Equal(t.IncludeInterface, other.IncludeInterface) {
		return false
	}
	if !slices.Equal(t.ExcludeInterface, other.ExcludeInterface) {
		return false
	}
	if !slices.Equal(t.IncludeUID, other.IncludeUID) {
		return false
	}
	if !slices.Equal(t.IncludeUIDRange, other.IncludeUIDRange) {
		return false
	}
	if !slices.Equal(t.ExcludeUID, other.ExcludeUID) {
		return false
	}
	if !slices.Equal(t.ExcludeUIDRange, other.ExcludeUIDRange) {
		return false
	}
	if !slices.Equal(t.IncludeAndroidUser, other.IncludeAndroidUser) {
		return false
	}
	if !slices.Equal(t.IncludePackage, other.IncludePackage) {
		return false
	}
	if !slices.Equal(t.ExcludePackage, other.ExcludePackage) {
		return false
	}
	if t.EndpointIndependentNat != other.EndpointIndependentNat {
		return false
	}
	if t.UDPTimeout != other.UDPTimeout {
		return false
	}
	if t.FileDescriptor != other.FileDescriptor {
		return false
	}

	if !slices.Equal(t.Inet4RouteAddress, other.Inet4RouteAddress) {
		return false
	}
	if !slices.Equal(t.Inet6RouteAddress, other.Inet6RouteAddress) {
		return false
	}
	if !slices.Equal(t.Inet4RouteExcludeAddress, other.Inet4RouteExcludeAddress) {
		return false
	}
	if !slices.Equal(t.Inet6RouteExcludeAddress, other.Inet6RouteExcludeAddress) {
		return false
	}

	return true
}
