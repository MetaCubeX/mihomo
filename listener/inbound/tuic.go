package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/tuic"
	"github.com/metacubex/mihomo/log"
)

type TuicOption struct {
	BaseOption
	Token                 []string          `inbound:"token,omitempty"`
	Users                 map[string]string `inbound:"users,omitempty"`
	Certificate           string            `inbound:"certificate"`
	PrivateKey            string            `inbound:"private-key"`
	CongestionController  string            `inbound:"congestion-controller,omitempty"`
	MaxIdleTime           int               `inbound:"max-idle-time,omitempty"`
	AuthenticationTimeout int               `inbound:"authentication-timeout,omitempty"`
	ALPN                  []string          `inbound:"alpn,omitempty"`
	MaxUdpRelayPacketSize int               `inbound:"max-udp-relay-packet-size,omitempty"`
	CWND                  int               `inbound:"cwnd,omitempty"`
	MuxOption             MuxOption         `inbound:"mux-option,omitempty"`
}

func (o TuicOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Tuic struct {
	*Base
	config *TuicOption
	l      *tuic.Listener
	ts     LC.TuicServer
}

func NewTuic(options *TuicOption) (*Tuic, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Tuic{
		Base:   base,
		config: options,
		ts: LC.TuicServer{
			Enable:                true,
			Listen:                base.RawAddress(),
			Token:                 options.Token,
			Users:                 options.Users,
			Certificate:           options.Certificate,
			PrivateKey:            options.PrivateKey,
			CongestionController:  options.CongestionController,
			MaxIdleTime:           options.MaxIdleTime,
			AuthenticationTimeout: options.AuthenticationTimeout,
			ALPN:                  options.ALPN,
			MaxUdpRelayPacketSize: options.MaxUdpRelayPacketSize,
			CWND:                  options.CWND,
			MuxOption:             options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (t *Tuic) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *Tuic) Address() string {
	if t.l != nil {
		for _, addr := range t.l.AddrList() {
			return addr.String()
		}
	}
	return ""
}

// Listen implements constant.InboundListener
func (t *Tuic) Listen(tunnel C.Tunnel) error {
	var err error
	t.l, err = tuic.New(t.ts, tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Tuic[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *Tuic) Close() error {
	return t.l.Close()
}

var _ C.InboundListener = (*Tuic)(nil)
