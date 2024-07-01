package config

import (
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
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
	GSO                    bool           `yaml:"gso" json:"gso,omitempty"`
	GSOMaxSize             uint32         `yaml:"gso-max-size" json:"gso-max-size,omitempty"`
	Inet4Address           []netip.Prefix `yaml:"inet4-address" json:"inet4-address,omitempty"`
	Inet6Address           []netip.Prefix `yaml:"inet6-address" json:"inet6-address,omitempty"`
	IPRoute2TableIndex     int            `yaml:"iproute2-table-index" json:"iproute2_table_index,omitempty"`
	IPRoute2RuleIndex      int            `yaml:"iproute2-rule-index" json:"iproute2_rule_index,omitempty"`
	AutoRedirect           bool           `yaml:"auto-redirect" json:"auto_redirect,omitempty"`
	AutoRedirectInputMark  uint32         `yaml:"auto-redirect-input-mark" json:"auto_redirect_input_mark,omitempty"`
	AutoRedirectOutputMark uint32         `yaml:"auto-redirect-output-mark" json:"auto_redirect_output_mark,omitempty"`
	StrictRoute            bool           `yaml:"strict-route" json:"strict-route,omitempty"`
	RouteAddress           []netip.Prefix `yaml:"route-address" json:"route_address,omitempty"`
	RouteAddressSet        []string       `yaml:"route-address-set" json:"route_address_set,omitempty"`
	RouteExcludeAddress    []netip.Prefix `yaml:"route-exclude-address" json:"route_exclude_address,omitempty"`
	RouteExcludeAddressSet []string       `yaml:"route-exclude-address-set" json:"route_exclude_address_set,omitempty"`
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
