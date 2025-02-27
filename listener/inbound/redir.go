package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/redir"
	"github.com/metacubex/mihomo/log"
)

type RedirOption struct {
	BaseOption
}

func (o RedirOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Redir struct {
	*Base
	config *RedirOption
	l      []*redir.Listener
}

func NewRedir(options *RedirOption) (*Redir, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Redir{
		Base:   base,
		config: options,
	}, nil
}

// Config implements constant.InboundListener
func (r *Redir) Config() C.InboundConfig {
	return r.config
}

// Address implements constant.InboundListener
func (r *Redir) Address() string {
	var addrList []string
	for _, l := range r.l {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (r *Redir) Listen(tunnel C.Tunnel) error {
	for _, addr := range strings.Split(r.RawAddress(), ",") {
		l, err := redir.New(addr, tunnel, r.Additions()...)
		if err != nil {
			return err
		}
		r.l = append(r.l, l)
	}
	log.Infoln("Redir[%s] proxy listening at: %s", r.Name(), r.Address())
	return nil
}

// Close implements constant.InboundListener
func (r *Redir) Close() error {
	var errs []error
	for _, l := range r.l {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close redir listener %s err: %w", l.Address(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*Redir)(nil)
