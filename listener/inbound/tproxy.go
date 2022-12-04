package inbound

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tproxy"
	"github.com/Dreamacro/clash/log"
)

type TProxyOption struct {
	BaseOption
	UDP *bool `inbound:"udp,omitempty"`
}

type TProxy struct {
	*Base
	lUDP *tproxy.UDPListener
	lTCP *tproxy.Listener
	udp  bool
}

func NewTProxy(options *TProxyOption) (*TProxy, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &TProxy{
		Base: base,
		udp:  options.UDP == nil || *options.UDP,
	}, nil

}

// Address implements constant.NewListener
func (t *TProxy) Address() string {
	return t.lTCP.Address()
}

// ReCreate implements constant.NewListener
func (t *TProxy) ReCreate(tcpIn chan<- C.ConnContext, udpIn chan<- *C.PacketAdapter) error {
	var err error
	_ = t.Close()
	t.lTCP, err = tproxy.NewWithInfos(t.RawAddress(), t.name, t.preferRulesName, tcpIn)
	if err != nil {
		return err
	}
	if t.udp {
		if t.lUDP != nil {
			t.lUDP, err = tproxy.NewUDPWithInfos(t.Address(), t.name, t.preferRulesName, udpIn)
			if err != nil {
				return err
			}
		}

	}
	log.Infoln("TProxy[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.NewListener
func (t *TProxy) Close() error {
	var tcpErr error
	var udpErr error
	if t.lTCP != nil {
		tcpErr = t.lTCP.Close()
	}
	if t.lUDP != nil {
		udpErr = t.lUDP.Close()
	}

	if tcpErr != nil && udpErr != nil {
		return fmt.Errorf("tcp close err: %s and udp close err: %s", tcpErr, udpErr)
	}
	if tcpErr != nil {
		return tcpErr
	}
	if udpErr != nil {
		return udpErr
	}
	return nil
}

var _ C.NewListener = (*TProxy)(nil)
