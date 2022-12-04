package inbound

import (
	"fmt"
	"sync"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/socks"
	"github.com/Dreamacro/clash/log"
)

type SocksOption struct {
	BaseOption
	UDP *bool `inbound:"udp,omitempty"`
}

type Socks struct {
	*Base
	mux sync.Mutex
	udp bool
	stl *socks.Listener
	sul *socks.UDPListener
}

func NewSocks(options *SocksOption) (*Socks, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Socks{
		Base: base,
		udp:  options.UDP == nil || *options.UDP,
	}, nil
}

// Close implements constant.NewListener
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

// Address implements constant.NewListener
func (s *Socks) Address() string {
	return s.stl.Address()
}

// ReCreate implements constant.NewListener
func (s *Socks) ReCreate(tcpIn chan<- C.ConnContext, udpIn chan<- *C.PacketAdapter) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	var err error
	_ = s.Close()
	if s.stl, err = socks.NewWithInfos(s.RawAddress(), s.name, s.preferRulesName, tcpIn); err != nil {
		return err
	}
	if s.udp {
		if s.sul, err = socks.NewUDPWithInfos(s.RawAddress(), s.name, s.preferRulesName, udpIn); err != nil {
			return err
		}
	}

	log.Infoln("SOCKS[%s] proxy listening at: %s", s.Name(), s.Address())
	return nil
}

var _ C.NewListener = (*Socks)(nil)
