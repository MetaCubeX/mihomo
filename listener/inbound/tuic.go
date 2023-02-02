package inbound

import (
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/tuic"
	"github.com/Dreamacro/clash/log"
)

type TuicOption struct {
	BaseOption
	Token                 []string `inbound:"token"`
	Certificate           string   `inbound:"certificate"`
	PrivateKey            string   `inbound:"private-key"`
	CongestionController  string   `inbound:"congestion-controller,omitempty"`
	MaxIdleTime           int      `inbound:"max-idle-timer,omitempty"`
	AuthenticationTimeout int      `inbound:"authentication-timeoutr,omitempty"`
	ALPN                  []string `inbound:"alpnr,omitempty"`
	MaxUdpRelayPacketSize int      `inbound:"max-udp-relay-packet-sizer,omitempty"`
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
			Certificate:           options.Certificate,
			PrivateKey:            options.PrivateKey,
			CongestionController:  options.CongestionController,
			MaxIdleTime:           options.MaxIdleTime,
			AuthenticationTimeout: options.AuthenticationTimeout,
			ALPN:                  options.ALPN,
			MaxUdpRelayPacketSize: options.MaxUdpRelayPacketSize,
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
func (t *Tuic) Listen(tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) error {
	var err error
	t.l, err = tuic.New(t.ts, tcpIn, udpIn, t.Additions()...)
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
