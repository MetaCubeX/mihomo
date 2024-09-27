package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/log"
)

type HTTPOption struct {
	BaseOption
	Users AuthUsers `inbound:"users,omitempty"`
}

func (o HTTPOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type HTTP struct {
	*Base
	config *HTTPOption
	l      *http.Listener
}

func NewHTTP(options *HTTPOption) (*HTTP, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &HTTP{
		Base:   base,
		config: options,
	}, nil
}

// Config implements constant.InboundListener
func (h *HTTP) Config() C.InboundConfig {
	return h.config
}

// Address implements constant.InboundListener
func (h *HTTP) Address() string {
	return h.l.Address()
}

// Listen implements constant.InboundListener
func (h *HTTP) Listen(tunnel C.Tunnel) error {
	var err error
	h.l, err = http.NewWithAuthenticator(h.RawAddress(), tunnel, h.config.Users.GetAuthStore(), h.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("HTTP[%s] proxy listening at: %s", h.Name(), h.Address())
	return nil
}

// Close implements constant.InboundListener
func (h *HTTP) Close() error {
	if h.l != nil {
		return h.l.Close()
	}
	return nil
}

var _ C.InboundListener = (*HTTP)(nil)
