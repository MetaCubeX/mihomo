package config

import (
	"encoding/json"
	"net/netip"

	C "github.com/Dreamacro/clash/constant"

	"gopkg.in/yaml.v3"
)

type ListenPrefix netip.Prefix

func (p ListenPrefix) MarshalJSON() ([]byte, error) {
	prefix := netip.Prefix(p)
	if !prefix.IsValid() {
		return json.Marshal(nil)
	}
	return json.Marshal(prefix.String())
}

func (p ListenPrefix) MarshalYAML() (interface{}, error) {
	prefix := netip.Prefix(p)
	if !prefix.IsValid() {
		return nil, nil
	}
	return prefix.String(), nil
}

func (p *ListenPrefix) UnmarshalJSON(bytes []byte) error {
	var value string
	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = ListenPrefix(prefix)
	return nil
}

func (p *ListenPrefix) UnmarshalYAML(node *yaml.Node) error {
	var value string
	err := node.Decode(&value)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = ListenPrefix(prefix)
	return nil
}

func (p ListenPrefix) Build() netip.Prefix {
	return netip.Prefix(p)
}

func StringSliceToListenPrefixSlice(ss []string) ([]ListenPrefix, error) {
	lps := make([]ListenPrefix, 0, len(ss))
	for _, s := range ss {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		lps = append(lps, ListenPrefix(prefix))
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
	Inet4Address           []ListenPrefix `yaml:"inet4-address" json:"inet4-address,omitempty"`
	Inet6Address           []ListenPrefix `yaml:"inet6-address" json:"inet6-address,omitempty"`
	StrictRoute            bool           `yaml:"strict-route" json:"strict-route,omitempty"`
	Inet4RouteAddress      []ListenPrefix `yaml:"inet4-route-address" json:"inet4-route-address,omitempty"`
	Inet6RouteAddress      []ListenPrefix `yaml:"inet6-route-address" json:"inet6-route-address,omitempty"`
	IncludeUID             []uint32       `yaml:"include-uid" json:"include-uid,omitempty"`
	IncludeUIDRange        []string       `yaml:"include-uid-range" json:"include-uid-range,omitempty"`
	ExcludeUID             []uint32       `yaml:"exclude-uid" json:"exclude-uid,omitempty"`
	ExcludeUIDRange        []string       `yaml:"exclude-uid-range" json:"exclude-uid-range,omitempty"`
	IncludeAndroidUser     []int          `yaml:"include-android-user" json:"include-android-user,omitempty"`
	IncludePackage         []string       `yaml:"include-package" json:"include-package,omitempty"`
	ExcludePackage         []string       `yaml:"exclude-package" json:"exclude-package,omitempty"`
	EndpointIndependentNat bool           `yaml:"endpoint-independent-nat" json:"endpoint-independent-nat,omitempty"`
	UDPTimeout             int64          `yaml:"udp-timeout" json:"udp-timeout,omitempty"`
}
