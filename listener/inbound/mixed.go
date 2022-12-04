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
	UDP *bool `inbound:"udp,omitempty"`
}

type Mixed struct {
	*Base
	l    *mixed.Listener
	lUDP *socks.UDPListener
	udp  bool
}

func NewMixed(options *MixedOption) (*Mixed, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Mixed{
		Base: base,
		udp:  options.UDP == nil || *options.UDP,
	}, nil
}

// Address implements constant.NewListener
func (m *Mixed) Address() string {
	return m.l.Address()
}

// ReCreate implements constant.NewListener
func (m *Mixed) ReCreate(tcpIn chan<- C.ConnContext, udpIn chan<- *C.PacketAdapter) error {
	var err error
	_ = m.Close()
	m.l, err = mixed.NewWithInfos(m.RawAddress(), m.name, m.preferRulesName, tcpIn)
	if err != nil {
		return err
	}
	if m.udp {
		m.lUDP, err = socks.NewUDPWithInfos(m.Address(), m.name, m.preferRulesName, udpIn)
		if err != nil {
			return err
		}
	}
	log.Infoln("Mixed(http+socks)[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

// Close implements constant.NewListener
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

var _ C.NewListener = (*Mixed)(nil)
