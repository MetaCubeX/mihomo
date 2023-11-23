package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_hysteria2"
	"github.com/metacubex/mihomo/log"
)

type Hysteria2Option struct {
	BaseOption
	Users                 map[string]string `inbound:"users,omitempty"`
	Obfs                  string            `inbound:"obfs,omitempty"`
	ObfsPassword          string            `inbound:"obfs-password,omitempty"`
	Certificate           string            `inbound:"certificate"`
	PrivateKey            string            `inbound:"private-key"`
	MaxIdleTime           int               `inbound:"max-idle-time,omitempty"`
	ALPN                  []string          `inbound:"alpn,omitempty"`
	Up                    string            `inbound:"up,omitempty"`
	Down                  string            `inbound:"down,omitempty"`
	IgnoreClientBandwidth bool              `inbound:"ignore-client-bandwidth,omitempty"`
	Masquerade            string            `inbound:"masquerade,omitempty"`
	CWND                  int               `inbound:"cwnd,omitempty"`
	MuxOption             MuxOption         `inbound:"mux-option,omitempty"`
}

func (o Hysteria2Option) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Hysteria2 struct {
	*Base
	config *Hysteria2Option
	l      *sing_hysteria2.Listener
	ts     LC.Hysteria2Server
}

func NewHysteria2(options *Hysteria2Option) (*Hysteria2, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Hysteria2{
		Base:   base,
		config: options,
		ts: LC.Hysteria2Server{
			Enable:                true,
			Listen:                base.RawAddress(),
			Users:                 options.Users,
			Obfs:                  options.Obfs,
			ObfsPassword:          options.ObfsPassword,
			Certificate:           options.Certificate,
			PrivateKey:            options.PrivateKey,
			MaxIdleTime:           options.MaxIdleTime,
			ALPN:                  options.ALPN,
			Up:                    options.Up,
			Down:                  options.Down,
			IgnoreClientBandwidth: options.IgnoreClientBandwidth,
			Masquerade:            options.Masquerade,
			CWND:                  options.CWND,
			MuxOption:             options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (t *Hysteria2) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *Hysteria2) Address() string {
	if t.l != nil {
		for _, addr := range t.l.AddrList() {
			return addr.String()
		}
	}
	return ""
}

// Listen implements constant.InboundListener
func (t *Hysteria2) Listen(tunnel C.Tunnel) error {
	var err error
	t.l, err = sing_hysteria2.New(t.ts, tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Hysteria2[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *Hysteria2) Close() error {
	return t.l.Close()
}

var _ C.InboundListener = (*Hysteria2)(nil)
