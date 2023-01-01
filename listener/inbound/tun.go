package inbound

import (
	"errors"
	"strings"

	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/sing_tun"
	"github.com/Dreamacro/clash/log"
)

type TunOption struct {
	BaseOption
	Device              string   `inbound:"device,omitempty"`
	Stack               string   `inbound:"stack,omitempty"`
	DNSHijack           []string `inbound:"dns-hijack,omitempty"`
	AutoRoute           bool     `inbound:"auto-route,omitempty"`
	AutoDetectInterface bool     `inbound:"auto-detect-interface,omitempty"`

	MTU                    uint32   `inbound:"mtu,omitempty"`
	Inet4Address           []string `inbound:"inet4_address,omitempty"`
	Inet6Address           []string `inbound:"inet6_address,omitempty"`
	StrictRoute            bool     `inbound:"strict_route,omitempty"`
	Inet4RouteAddress      []string `inbound:"inet4_route_address,omitempty"`
	Inet6RouteAddress      []string `inbound:"inet6_route_address,omitempty"`
	IncludeUID             []uint32 `inbound:"include_uid,omitempty"`
	IncludeUIDRange        []string `inbound:"include_uid_range,omitempty"`
	ExcludeUID             []uint32 `inbound:"exclude_uid,omitempty"`
	ExcludeUIDRange        []string `inbound:"exclude_uid_range,omitempty"`
	IncludeAndroidUser     []int    `inbound:"include_android_user,omitempty"`
	IncludePackage         []string `inbound:"include_package,omitempty"`
	ExcludePackage         []string `inbound:"exclude_package,omitempty"`
	EndpointIndependentNat bool     `inbound:"endpoint_independent_nat,omitempty"`
	UDPTimeout             int64    `inbound:"udp_timeout,omitempty"`
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
	inet4Address, err := LC.StringSliceToListenPrefixSlice(options.Inet4Address)
	if err != nil {
		return nil, err
	}
	inet6Address, err := LC.StringSliceToListenPrefixSlice(options.Inet6Address)
	if err != nil {
		return nil, err
	}
	inet4RouteAddress, err := LC.StringSliceToListenPrefixSlice(options.Inet4RouteAddress)
	if err != nil {
		return nil, err
	}
	inet6RouteAddress, err := LC.StringSliceToListenPrefixSlice(options.Inet6RouteAddress)
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
			Inet4Address:           inet4Address,
			Inet6Address:           inet6Address,
			StrictRoute:            options.StrictRoute,
			Inet4RouteAddress:      inet4RouteAddress,
			Inet6RouteAddress:      inet6RouteAddress,
			IncludeUID:             options.IncludeUID,
			IncludeUIDRange:        options.IncludeUIDRange,
			ExcludeUID:             options.ExcludeUID,
			ExcludeUIDRange:        options.ExcludeUIDRange,
			IncludeAndroidUser:     options.IncludeAndroidUser,
			IncludePackage:         options.IncludePackage,
			ExcludePackage:         options.ExcludePackage,
			EndpointIndependentNat: options.EndpointIndependentNat,
			UDPTimeout:             options.UDPTimeout,
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
func (t *Tun) Listen(tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) error {
	var err error
	t.l, err = sing_tun.New(t.tun, tcpIn, udpIn, t.Additions()...)
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
