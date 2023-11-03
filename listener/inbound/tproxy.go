package inbound

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/tproxy"
	"github.com/metacubex/mihomo/log"
)

type TProxyOption struct {
	BaseOption
	UDP bool `inbound:"udp,omitempty"`
}

func (o TProxyOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type TProxy struct {
	*Base
	config *TProxyOption
	lUDP   *tproxy.UDPListener
	lTCP   *tproxy.Listener
	udp    bool
}

func NewTProxy(options *TProxyOption) (*TProxy, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &TProxy{
		Base:   base,
		config: options,
		udp:    options.UDP,
	}, nil

}

// Config implements constant.InboundListener
func (t *TProxy) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *TProxy) Address() string {
	return t.lTCP.Address()
}

// Listen implements constant.InboundListener
func (t *TProxy) Listen(tunnel C.Tunnel) error {
	var err error
	t.lTCP, err = tproxy.New(t.RawAddress(), tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	if t.udp {
		t.lUDP, err = tproxy.NewUDP(t.RawAddress(), tunnel, t.Additions()...)
		if err != nil {
			return err
		}
	}
	log.Infoln("TProxy[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
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

var _ C.InboundListener = (*TProxy)(nil)
