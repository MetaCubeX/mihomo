package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/log"
)

type ShadowSocksOption struct {
	BaseOption
	Password  string    `inbound:"password"`
	Cipher    string    `inbound:"cipher"`
	UDP       bool      `inbound:"udp,omitempty"`
	MuxOption MuxOption `inbound:"mux-option,omitempty"`
}

func (o ShadowSocksOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ShadowSocks struct {
	*Base
	config *ShadowSocksOption
	l      C.MultiAddrListener
	ss     LC.ShadowsocksServer
}

func NewShadowSocks(options *ShadowSocksOption) (*ShadowSocks, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &ShadowSocks{
		Base:   base,
		config: options,
		ss: LC.ShadowsocksServer{
			Enable:    true,
			Listen:    base.RawAddress(),
			Password:  options.Password,
			Cipher:    options.Cipher,
			Udp:       options.UDP,
			MuxOption: options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (s *ShadowSocks) Config() C.InboundConfig {
	return s.config
}

// Address implements constant.InboundListener
func (s *ShadowSocks) Address() string {
	if s.l != nil {
		for _, addr := range s.l.AddrList() {
			return addr.String()
		}
	}
	return ""
}

// Listen implements constant.InboundListener
func (s *ShadowSocks) Listen(tunnel C.Tunnel) error {
	var err error
	s.l, err = sing_shadowsocks.New(s.ss, tunnel, s.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("ShadowSocks[%s] proxy listening at: %s", s.Name(), s.Address())
	return nil
}

// Close implements constant.InboundListener
func (s *ShadowSocks) Close() error {
	return s.l.Close()
}

var _ C.InboundListener = (*ShadowSocks)(nil)
