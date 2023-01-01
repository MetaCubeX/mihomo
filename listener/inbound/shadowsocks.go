package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/sing_shadowsocks"
	"github.com/Dreamacro/clash/log"
)

type ShadowSocksOption struct {
	BaseOption
	Password string `inbound:"password"`
	Cipher   string `inbound:"cipher"`
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
			Enable:   true,
			Listen:   base.RawAddress(),
			Password: options.Password,
			Cipher:   options.Cipher,
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
func (s *ShadowSocks) Listen(tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) error {
	var err error
	s.l, err = sing_shadowsocks.New(s.ss, tcpIn, udpIn, s.Additions()...)
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
