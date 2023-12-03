package inbound

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
)

type Base struct {
	config       *BaseOption
	name         string
	specialRules string
	listenAddr   netip.Addr
	port         int
}

func NewBase(options *BaseOption) (*Base, error) {
	if options.Listen == "" {
		options.Listen = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(options.Listen)
	if err != nil {
		return nil, err
	}
	return &Base{
		name:         options.Name(),
		listenAddr:   addr,
		specialRules: options.SpecialRules,
		port:         options.Port,
		config:       options,
	}, nil
}

// Config implements constant.InboundListener
func (b *Base) Config() C.InboundConfig {
	return b.config
}

// Address implements constant.InboundListener
func (b *Base) Address() string {
	return b.RawAddress()
}

// Close implements constant.InboundListener
func (*Base) Close() error {
	return nil
}

// Name implements constant.InboundListener
func (b *Base) Name() string {
	return b.name
}

// RawAddress implements constant.InboundListener
func (b *Base) RawAddress() string {
	return net.JoinHostPort(b.listenAddr.String(), strconv.Itoa(int(b.port)))
}

// Listen implements constant.InboundListener
func (*Base) Listen(tunnel C.Tunnel) error {
	return nil
}

func (b *Base) Additions() []inbound.Addition {
	return b.config.Additions()
}

var _ C.InboundListener = (*Base)(nil)

type BaseOption struct {
	NameStr      string `inbound:"name"`
	Listen       string `inbound:"listen,omitempty"`
	Port         int    `inbound:"port,omitempty"`
	SpecialRules string `inbound:"rule,omitempty"`
	SpecialProxy string `inbound:"proxy,omitempty"`
}

func (o BaseOption) Name() string {
	return o.NameStr
}

func (o BaseOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

func (o BaseOption) Additions() []inbound.Addition {
	return []inbound.Addition{
		inbound.WithInName(o.NameStr),
		inbound.WithSpecialRules(o.SpecialRules),
		inbound.WithSpecialProxy(o.SpecialProxy),
	}
}

var _ C.InboundConfig = (*BaseOption)(nil)

func optionToString(option any) string {
	str, _ := json.Marshal(option)
	return string(str)
}
