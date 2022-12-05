package inbound

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"github.com/Dreamacro/clash/listener/mixed"
	"github.com/Dreamacro/clash/listener/socks"
)

type MixedOption struct {
	BaseOption
	UDP bool `inbound:"udp,omitempty"`
}

func (o MixedOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Mixed struct {
	*Base
	config *MixedOption
	l      *mixed.Listener
	lUDP   *socks.UDPListener
	udp    bool
}

func NewMixed(options *MixedOption) (*Mixed, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Mixed{
		Base:   base,
		config: options,
		udp:    options.UDP,
	}, nil
}

// Config implements constant.InboundListener
func (m *Mixed) Config() C.InboundConfig {
	return m.config
}

// Address implements constant.InboundListener
func (m *Mixed) Address() string {
	return m.l.Address()
}

// Listen implements constant.InboundListener
func (m *Mixed) Listen(tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) error {
	var err error
	m.l, err = mixed.New(m.RawAddress(), tcpIn, m.Additions()...)
	if err != nil {
		return err
	}
	if m.udp {
		m.lUDP, err = socks.NewUDP(m.RawAddress(), udpIn, m.Additions()...)
		if err != nil {
			return err
		}
	}
	log.Infoln("Mixed(http+socks)[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

// Close implements constant.InboundListener
func (m *Mixed) Close() error {
	var err error
	if m.l != nil {
		if tcpErr := m.l.Close(); tcpErr != nil {
			err = tcpErr
		}
	}
	if m.udp && m.lUDP != nil {
		if udpErr := m.lUDP.Close(); udpErr != nil {
			if err == nil {
				err = udpErr
			} else {
				return fmt.Errorf("close tcp err: %s, close udp err: %s", err.Error(), udpErr.Error())
			}
		}
	}
	return err
}

var _ C.InboundListener = (*Mixed)(nil)
