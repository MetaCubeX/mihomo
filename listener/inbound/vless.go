package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/log"
)

type VlessOption struct {
	BaseOption
	Users         []VlessUser   `inbound:"users"`
	WsPath        string        `inbound:"ws-path,omitempty"`
	Certificate   string        `inbound:"certificate,omitempty"`
	PrivateKey    string        `inbound:"private-key,omitempty"`
	RealityConfig RealityConfig `inbound:"reality-config,omitempty"`
	MuxOption     MuxOption     `inbound:"mux-option,omitempty"`
}

type VlessUser struct {
	Username string `inbound:"username,omitempty"`
	UUID     string `inbound:"uuid"`
	Flow     string `inbound:"flow,omitempty"`
}

func (o VlessOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Vless struct {
	*Base
	config *VlessOption
	l      C.MultiAddrListener
	vs     LC.VlessServer
}

func NewVless(options *VlessOption) (*Vless, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users := make([]LC.VlessUser, len(options.Users))
	for i, v := range options.Users {
		users[i] = LC.VlessUser{
			Username: v.Username,
			UUID:     v.UUID,
			Flow:     v.Flow,
		}
	}
	return &Vless{
		Base:   base,
		config: options,
		vs: LC.VlessServer{
			Enable:        true,
			Listen:        base.RawAddress(),
			Users:         users,
			WsPath:        options.WsPath,
			Certificate:   options.Certificate,
			PrivateKey:    options.PrivateKey,
			RealityConfig: options.RealityConfig.Build(),
			MuxOption:     options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *Vless) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *Vless) Address() string {
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			return addr.String()
		}
	}
	return ""
}

// Listen implements constant.InboundListener
func (v *Vless) Listen(tunnel C.Tunnel) error {
	var err error
	users := make([]LC.VlessUser, len(v.config.Users))
	for i, v := range v.config.Users {
		users[i] = LC.VlessUser{
			Username: v.Username,
			UUID:     v.UUID,
			Flow:     v.Flow,
		}
	}
	v.l, err = sing_vless.New(v.vs, tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Vless[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *Vless) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*Vless)(nil)
