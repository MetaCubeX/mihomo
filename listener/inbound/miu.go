package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/miu"
	"github.com/metacubex/mihomo/log"
)

type MiuOption struct {
	BaseOption
	Users          map[string]string `inbound:"users,omitempty"`
	Certificate    string            `inbound:"certificate,omitempty"`
	PrivateKey     string            `inbound:"private-key,omitempty"`
	ClientAuthType string            `inbound:"client-auth-type,omitempty"`
	ClientAuthCert string            `inbound:"client-auth-cert,omitempty"`
	EchKey         string            `inbound:"ech-key,omitempty"`
	RealityConfig  RealityConfig     `inbound:"reality-config,omitempty"`
	PaddingScheme  string            `inbound:"padding-scheme,omitempty"`
}

func (o MiuOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Miu struct {
	*Base
	config *MiuOption
	l      C.MultiAddrListener
	vs     LC.MiuServer
}

func NewMiu(options *MiuOption) (*Miu, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Miu{
		Base:   base,
		config: options,
		vs: LC.MiuServer{
			Enable:         true,
			Listen:         base.RawAddress(),
			Users:          options.Users,
			Certificate:    options.Certificate,
			PrivateKey:     options.PrivateKey,
			ClientAuthType: options.ClientAuthType,
			ClientAuthCert: options.ClientAuthCert,
			EchKey:         options.EchKey,
			RealityConfig:  options.RealityConfig.Build(),
			PaddingScheme:  options.PaddingScheme,
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *Miu) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *Miu) Address() string {
	var addrList []string
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (v *Miu) Listen(tunnel C.Tunnel) error {
	var err error
	v.l, err = miu.New(v.vs, v.ListenConfig(), tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Miu[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *Miu) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*Miu)(nil)
