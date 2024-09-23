package inbound

import (
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
)

type TunOption struct {
	BaseOption
	Device              string   `inbound:"device,omitempty"`
	Stack               string   `inbound:"stack,omitempty"`
	DNSHijack           []string `inbound:"dns-hijack,omitempty"`
	AutoRoute           bool     `inbound:"auto-route,omitempty"`
	AutoDetectInterface bool     `inbound:"auto-detect-interface,omitempty"`

	MTU                    uint32   `inbound:"mtu,omitempty"`
	GSO                    bool     `inbound:"gso,omitempty"`
	GSOMaxSize             uint32   `inbound:"gso-max-size,omitempty"`
	Inet4Address           []string `inbound:"inet4-address,omitempty"`
	Inet6Address           []string `inbound:"inet6-address,omitempty"`
	IPRoute2TableIndex     int      `inbound:"iproute2-table-index"`
	IPRoute2RuleIndex      int      `inbound:"iproute2-rule-index"`
	AutoRedirect           bool     `inbound:"auto-redirect"`
	AutoRedirectInputMark  uint32   `inbound:"auto-redirect-input-mark"`
	AutoRedirectOutputMark uint32   `inbound:"auto-redirect-output-mark"`
	StrictRoute            bool     `inbound:"strict-route,omitempty"`
	RouteAddress           []string `inbound:"route-address"`
	RouteAddressSet        []string `inbound:"route-address-set"`
	RouteExcludeAddress    []string `inbound:"route-exclude-address"`
	RouteExcludeAddressSet []string `inbound:"route-exclude-address-set"`
	IncludeInterface       []string `inbound:"include-interface,omitempty"`
	ExcludeInterface       []string `inbound:"exclude-interface"`
	IncludeUID             []uint32 `inbound:"include-uid,omitempty"`
	IncludeUIDRange        []string `inbound:"include-uid-range,omitempty"`
	ExcludeUID             []uint32 `inbound:"exclude-uid,omitempty"`
	ExcludeUIDRange        []string `inbound:"exclude-uid-range,omitempty"`
	IncludeAndroidUser     []int    `inbound:"include-android-user,omitempty"`
	IncludePackage         []string `inbound:"include-package,omitempty"`
	ExcludePackage         []string `inbound:"exclude-package,omitempty"`
	EndpointIndependentNat bool     `inbound:"endpoint-independent-nat,omitempty"`
	UDPTimeout             int64    `inbound:"udp-timeout,omitempty"`
	FileDescriptor         int      `inbound:"file-descriptor,omitempty"`

	Inet4RouteAddress        []string `inbound:"inet4-route-address,omitempty"`
	Inet6RouteAddress        []string `inbound:"inet6-route-address,omitempty"`
	Inet4RouteExcludeAddress []string `inbound:"inet4-route-exclude-address,omitempty"`
	Inet6RouteExcludeAddress []string `inbound:"inet6-route-exclude-address,omitempty"`
}

func (o TunOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Tun struct {
	*Base
	config *TunOption
	l      *sing_tun.Listener
	tun    LC.Tun
}

func NewTun(options *TunOption) (*Tun, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	stack, exist := C.StackTypeMapping[strings.ToLower(options.Stack)]
	if !exist {
		return nil, errors.New("invalid tun stack")
	}

	routeAddress, err := LC.StringSliceToNetipPrefixSlice(options.RouteAddress)
	if err != nil {
		return nil, err
	}
	routeExcludeAddress, err := LC.StringSliceToNetipPrefixSlice(options.RouteExcludeAddress)
	if err != nil {
		return nil, err
	}

	inet4Address, err := LC.StringSliceToNetipPrefixSlice(options.Inet4Address)
	if err != nil {
		return nil, err
	}
	inet6Address, err := LC.StringSliceToNetipPrefixSlice(options.Inet6Address)
	if err != nil {
		return nil, err
	}
	inet4RouteAddress, err := LC.StringSliceToNetipPrefixSlice(options.Inet4RouteAddress)
	if err != nil {
		return nil, err
	}
	inet6RouteAddress, err := LC.StringSliceToNetipPrefixSlice(options.Inet6RouteAddress)
	if err != nil {
		return nil, err
	}
	inet4RouteExcludeAddress, err := LC.StringSliceToNetipPrefixSlice(options.Inet4RouteExcludeAddress)
	if err != nil {
		return nil, err
	}
	inet6RouteExcludeAddress, err := LC.StringSliceToNetipPrefixSlice(options.Inet6RouteExcludeAddress)
	if err != nil {
		return nil, err
	}
	return &Tun{
		Base:   base,
		config: options,
		tun: LC.Tun{
			Enable:                 true,
			Device:                 options.Device,
			Stack:                  stack,
			DNSHijack:              options.DNSHijack,
			AutoRoute:              options.AutoRoute,
			AutoDetectInterface:    options.AutoDetectInterface,
			MTU:                    options.MTU,
			GSO:                    options.GSO,
			GSOMaxSize:             options.GSOMaxSize,
			Inet4Address:           inet4Address,
			Inet6Address:           inet6Address,
			IPRoute2TableIndex:     options.IPRoute2TableIndex,
			IPRoute2RuleIndex:      options.IPRoute2RuleIndex,
			AutoRedirect:           options.AutoRedirect,
			AutoRedirectInputMark:  options.AutoRedirectInputMark,
			AutoRedirectOutputMark: options.AutoRedirectOutputMark,
			StrictRoute:            options.StrictRoute,
			RouteAddress:           routeAddress,
			RouteAddressSet:        options.RouteAddressSet,
			RouteExcludeAddress:    routeExcludeAddress,
			RouteExcludeAddressSet: options.RouteExcludeAddressSet,
			IncludeInterface:       options.IncludeInterface,
			ExcludeInterface:       options.ExcludeInterface,
			IncludeUID:             options.IncludeUID,
			IncludeUIDRange:        options.IncludeUIDRange,
			ExcludeUID:             options.ExcludeUID,
			ExcludeUIDRange:        options.ExcludeUIDRange,
			IncludeAndroidUser:     options.IncludeAndroidUser,
			IncludePackage:         options.IncludePackage,
			ExcludePackage:         options.ExcludePackage,
			EndpointIndependentNat: options.EndpointIndependentNat,
			UDPTimeout:             options.UDPTimeout,
			FileDescriptor:         options.FileDescriptor,

			Inet4RouteAddress:        inet4RouteAddress,
			Inet6RouteAddress:        inet6RouteAddress,
			Inet4RouteExcludeAddress: inet4RouteExcludeAddress,
			Inet6RouteExcludeAddress: inet6RouteExcludeAddress,
		},
	}, nil
}

// Config implements constant.InboundListener
func (t *Tun) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *Tun) Address() string {
	return t.l.Address()
}

// Listen implements constant.InboundListener
func (t *Tun) Listen(tunnel C.Tunnel) error {
	var err error
	t.l, err = sing_tun.New(t.tun, tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Tun[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *Tun) Close() error {
	return t.l.Close()
}

var _ C.InboundListener = (*Tun)(nil)
