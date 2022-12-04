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
	CongestionController  string   `inbound:"congestion-controllerr,omitempty"`
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
}

func NewTuic(options *TuicOption) (*Tuic, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Tuic{
		Base:   base,
		config: options,
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
	t.l, err = tuic.New(LC.TuicServer{
		Enable:                true,
		Listen:                t.RawAddress(),
		Token:                 t.config.Token,
		Certificate:           t.config.Certificate,
		PrivateKey:            t.config.PrivateKey,
		CongestionController:  t.config.CongestionController,
		MaxIdleTime:           t.config.MaxIdleTime,
		AuthenticationTimeout: t.config.AuthenticationTimeout,
		ALPN:                  t.config.ALPN,
		MaxUdpRelayPacketSize: t.config.MaxUdpRelayPacketSize,
	}, tcpIn, udpIn)
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
