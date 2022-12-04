package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/http"
	"github.com/Dreamacro/clash/log"
)

type HTTPOption struct {
	BaseOption
}
type HTTP struct {
	*Base
	l *http.Listener
}

func NewHTTP(options *HTTPOption) (*HTTP, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &HTTP{
		Base: base,
	}, nil
}

// Address implements constant.NewListener
func (h *HTTP) Address() string {
	return h.l.Address()
}

// ReCreate implements constant.NewListener
func (h *HTTP) Listen(tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) error {
	var err error
	h.l, err = http.NewWithInfos(h.RawAddress(), h.name, h.preferRulesName, tcpIn)
	if err != nil {
		return err
	}
	log.Infoln("HTTP[%s] proxy listening at: %s", h.Name(), h.Address())
	return nil
}

// Close implements constant.NewListener
func (h *HTTP) Close() error {
	if h.l != nil {
		return h.l.Close()
	}
	return nil
}

var _ C.NewListener = (*HTTP)(nil)
