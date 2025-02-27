package inbound

import (
	"errors"
	"fmt"
	"strings"

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
	lUDP   []*tproxy.UDPListener
	lTCP   []*tproxy.Listener
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
	var addrList []string
	for _, l := range t.lTCP {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (t *TProxy) Listen(tunnel C.Tunnel) error {
	for _, addr := range strings.Split(t.RawAddress(), ",") {
		lTCP, err := tproxy.New(addr, tunnel, t.Additions()...)
		if err != nil {
			return err
		}
		t.lTCP = append(t.lTCP, lTCP)
		if t.udp {
			lUDP, err := tproxy.NewUDP(addr, tunnel, t.Additions()...)
			if err != nil {
				return err
			}
			t.lUDP = append(t.lUDP, lUDP)
		}
	}
	log.Infoln("TProxy[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *TProxy) Close() error {
	var errs []error
	for _, l := range t.lTCP {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close tcp listener %s err: %w", l.Address(), err))
		}
	}
	for _, l := range t.lUDP {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close udp listener %s err: %w", l.Address(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*TProxy)(nil)
