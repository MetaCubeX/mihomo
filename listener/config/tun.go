package config

import (
	"net/netip"

	C "github.com/Dreamacro/clash/constant"
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
	RedirectToTun       []string   `yaml:"-" json:"-"`

	MTU                    uint32         `yaml:"mtu" json:"mtu,omitempty"`
	Inet4Address           []netip.Prefix `yaml:"inet4-address" json:"inet4-address,omitempty"`
	Inet6Address           []netip.Prefix `yaml:"inet6-address" json:"inet6-address,omitempty"`
	StrictRoute            bool           `yaml:"strict-route" json:"strict-route,omitempty"`
	Inet4RouteAddress      []netip.Prefix `yaml:"inet4-route-address" json:"inet4-route-address,omitempty"`
	Inet6RouteAddress      []netip.Prefix `yaml:"inet6-route-address" json:"inet6-route-address,omitempty"`
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
}
