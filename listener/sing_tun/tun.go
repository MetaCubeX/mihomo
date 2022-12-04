package sing_tun

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

type Tun struct {
	Enable              bool
	Device              string
	Stack               C.TUNStack
	DNSHijack           []netip.AddrPort
	AutoRoute           bool
	AutoDetectInterface bool
	RedirectToTun       []string

	MTU                    uint32
	Inet4Address           []ListenPrefix
	Inet6Address           []ListenPrefix
	StrictRoute            bool
	Inet4RouteAddress      []ListenPrefix
	Inet6RouteAddress      []ListenPrefix
	IncludeUID             []uint32
	IncludeUIDRange        []string
	ExcludeUID             []uint32
	ExcludeUIDRange        []string
	IncludeAndroidUser     []int
	IncludePackage         []string
	ExcludePackage         []string
	EndpointIndependentNat bool
	UDPTimeout             int64
}
