package inbound

import (
	"encoding"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
)

type TunOption struct {
	BaseOption
	Device              string     `inbound:"device,omitempty"`
	Stack               C.TUNStack `inbound:"stack,omitempty"`
	DNSHijack           []string   `inbound:"dns-hijack,omitempty"`
	AutoRoute           bool       `inbound:"auto-route,omitempty"`
	AutoDetectInterface bool       `inbound:"auto-detect-interface,omitempty"`

	MTU                    uint32         `inbound:"mtu,omitempty"`
	GSO                    bool           `inbound:"gso,omitempty"`
	GSOMaxSize             uint32         `inbound:"gso-max-size,omitempty"`
	Inet4Address           []netip.Prefix `inbound:"inet4-address,omitempty"`
	Inet6Address           []netip.Prefix `inbound:"inet6-address,omitempty"`
	IPRoute2TableIndex     int            `inbound:"iproute2-table-index,omitempty"`
	IPRoute2RuleIndex      int            `inbound:"iproute2-rule-index,omitempty"`
	AutoRedirect           bool           `inbound:"auto-redirect,omitempty"`
	AutoRedirectInputMark  uint32         `inbound:"auto-redirect-input-mark,omitempty"`
	AutoRedirectOutputMark uint32         `inbound:"auto-redirect-output-mark,omitempty"`
	LoopbackAddress        []netip.Addr   `inbound:"loopback-address,omitempty"`
	StrictRoute            bool           `inbound:"strict-route,omitempty"`
	RouteAddress           []netip.Prefix `inbound:"route-address,omitempty"`
	RouteAddressSet        []string       `inbound:"route-address-set,omitempty"`
	RouteExcludeAddress    []netip.Prefix `inbound:"route-exclude-address,omitempty"`
	RouteExcludeAddressSet []string       `inbound:"route-exclude-address-set,omitempty"`
	IncludeInterface       []string       `inbound:"include-interface,omitempty"`
	ExcludeInterface       []string       `inbound:"exclude-interface,omitempty"`
	IncludeUID             []uint32       `inbound:"include-uid,omitempty"`
	IncludeUIDRange        []string       `inbound:"include-uid-range,omitempty"`
	ExcludeUID             []uint32       `inbound:"exclude-uid,omitempty"`
	ExcludeUIDRange        []string       `inbound:"exclude-uid-range,omitempty"`
	ExcludeSrcPort         []uint16       `inbound:"exclude-src-port,omitempty"`
	ExcludeSrcPortRange    []string       `inbound:"exclude-src-port-range,omitempty"`
	ExcludeDstPort         []uint16       `inbound:"exclude-dst-port,omitempty"`
	ExcludeDstPortRange    []string       `inbound:"exclude-dst-port-range,omitempty"`
	IncludeAndroidUser     []int          `inbound:"include-android-user,omitempty"`
	IncludePackage         []string       `inbound:"include-package,omitempty"`
	ExcludePackage         []string       `inbound:"exclude-package,omitempty"`
	EndpointIndependentNat bool           `inbound:"endpoint-independent-nat,omitempty"`
	UDPTimeout             int64          `inbound:"udp-timeout,omitempty"`
	DisableICMPForwarding  bool           `inbound:"disable-icmp-forwarding,omitempty"`
	FileDescriptor         int            `inbound:"file-descriptor,omitempty"`

	Inet4RouteAddress        []netip.Prefix `inbound:"inet4-route-address,omitempty"`
	Inet6RouteAddress        []netip.Prefix `inbound:"inet6-route-address,omitempty"`
	Inet4RouteExcludeAddress []netip.Prefix `inbound:"inet4-route-exclude-address,omitempty"`
	Inet6RouteExcludeAddress []netip.Prefix `inbound:"inet6-route-exclude-address,omitempty"`

	// darwin special config
	RecvMsgX bool `inbound:"recvmsgx,omitempty"`
	SendMsgX bool `inbound:"sendmsgx,omitempty"`
}

var _ encoding.TextUnmarshaler = (*netip.Addr)(nil)   // ensure netip.Addr can decode direct by structure package
var _ encoding.TextUnmarshaler = (*netip.Prefix)(nil) // ensure netip.Prefix can decode direct by structure package
var _ encoding.TextUnmarshaler = (*C.TUNStack)(nil)   // ensure C.TUNStack can decode direct by structure package

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
	return &Tun{
		Base:   base,
		config: options,
		tun: LC.Tun{
			Enable:                 true,
			Device:                 options.Device,
			Stack:                  options.Stack,
			DNSHijack:              options.DNSHijack,
			AutoRoute:              options.AutoRoute,
			AutoDetectInterface:    options.AutoDetectInterface,
			MTU:                    options.MTU,
			GSO:                    options.GSO,
			GSOMaxSize:             options.GSOMaxSize,
			Inet4Address:           options.Inet4Address,
			Inet6Address:           options.Inet6Address,
			IPRoute2TableIndex:     options.IPRoute2TableIndex,
			IPRoute2RuleIndex:      options.IPRoute2RuleIndex,
			AutoRedirect:           options.AutoRedirect,
			AutoRedirectInputMark:  options.AutoRedirectInputMark,
			AutoRedirectOutputMark: options.AutoRedirectOutputMark,
			LoopbackAddress:        options.LoopbackAddress,
			StrictRoute:            options.StrictRoute,
			RouteAddress:           options.RouteAddress,
			RouteAddressSet:        options.RouteAddressSet,
			RouteExcludeAddress:    options.RouteExcludeAddress,
			RouteExcludeAddressSet: options.RouteExcludeAddressSet,
			IncludeInterface:       options.IncludeInterface,
			ExcludeInterface:       options.ExcludeInterface,
			IncludeUID:             options.IncludeUID,
			IncludeUIDRange:        options.IncludeUIDRange,
			ExcludeUID:             options.ExcludeUID,
			ExcludeUIDRange:        options.ExcludeUIDRange,
			ExcludeSrcPort:         options.ExcludeSrcPort,
			ExcludeSrcPortRange:    options.ExcludeSrcPortRange,
			ExcludeDstPort:         options.ExcludeDstPort,
			ExcludeDstPortRange:    options.ExcludeDstPortRange,
			IncludeAndroidUser:     options.IncludeAndroidUser,
			IncludePackage:         options.IncludePackage,
			ExcludePackage:         options.ExcludePackage,
			EndpointIndependentNat: options.EndpointIndependentNat,
			UDPTimeout:             options.UDPTimeout,
			DisableICMPForwarding:  options.DisableICMPForwarding,
			FileDescriptor:         options.FileDescriptor,

			Inet4RouteAddress:        options.Inet4RouteAddress,
			Inet6RouteAddress:        options.Inet6RouteAddress,
			Inet4RouteExcludeAddress: options.Inet4RouteExcludeAddress,
			Inet6RouteExcludeAddress: options.Inet6RouteExcludeAddress,

			RecvMsgX: options.RecvMsgX,
			SendMsgX: options.SendMsgX,
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
