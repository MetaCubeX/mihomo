package inbound

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/log"
)

type SocksOption struct {
	BaseOption
	UDP bool `inbound:"udp,omitempty"`
}

func (o SocksOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Socks struct {
	*Base
	config *SocksOption
	udp    bool
	stl    *socks.Listener
	sul    *socks.UDPListener
}

func NewSocks(options *SocksOption) (*Socks, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Socks{
		Base:   base,
		config: options,
		udp:    options.UDP,
	}, nil
}

// Config implements constant.InboundListener
func (s *Socks) Config() C.InboundConfig {
	return s.config
}

// Close implements constant.InboundListener
func (s *Socks) Close() error {
	var err error
	if s.stl != nil {
		if tcpErr := s.stl.Close(); tcpErr != nil {
			err = tcpErr
		}
	}
	if s.udp && s.sul != nil {
		if udpErr := s.sul.Close(); udpErr != nil {
			if err == nil {
				err = udpErr
			} else {
				return fmt.Errorf("close tcp err: %s, close udp err: %s", err.Error(), udpErr.Error())
			}
		}
	}

	return err
}

// Address implements constant.InboundListener
func (s *Socks) Address() string {
	return s.stl.Address()
}

// Listen implements constant.InboundListener
func (s *Socks) Listen(tunnel C.Tunnel) error {
	var err error
	if s.stl, err = socks.New(s.RawAddress(), tunnel, s.Additions()...); err != nil {
		return err
	}
	if s.udp {
		if s.sul, err = socks.NewUDP(s.RawAddress(), tunnel, s.Additions()...); err != nil {
			return err
		}
	}

	log.Infoln("SOCKS[%s] proxy listening at: %s", s.Name(), s.Address())
	return nil
}

var _ C.InboundListener = (*Socks)(nil)
