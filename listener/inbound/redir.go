package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/redir"
	"github.com/Dreamacro/clash/log"
)

type RedirOption struct {
	BaseOption
}

type Redir struct {
	*Base
	l *redir.Listener
}

func NewRedir(options *RedirOption) (*Redir, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Redir{
		Base: base,
	}, nil
}

// Address implements constant.NewListener
func (r *Redir) Address() string {
	return r.l.Address()
}

// ReCreate implements constant.NewListener
func (r *Redir) ReCreate(tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) error {
	var err error
	_ = r.Close()
	r.l, err = redir.NewWithInfos(r.Address(), r.name, r.preferRulesName, tcpIn)
	if err != nil {
		return err
	}
	log.Infoln("Redir[%s] proxy listening at: %s", r.Name(), r.Address())
	return nil
}

// Close implements constant.NewListener
func (r *Redir) Close() error {
	if r.l != nil {
		r.l.Close()
	}
	return nil
}

var _ C.NewListener = (*Redir)(nil)
