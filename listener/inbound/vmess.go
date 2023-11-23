package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/log"
)

type VmessOption struct {
	BaseOption
	Users       []VmessUser `inbound:"users"`
	WsPath      string      `inbound:"ws-path,omitempty"`
	Certificate string      `inbound:"certificate,omitempty"`
	PrivateKey  string      `inbound:"private-key,omitempty"`
	MuxOption   MuxOption   `inbound:"mux-option,omitempty"`
}

type VmessUser struct {
	Username string `inbound:"username,omitempty"`
	UUID     string `inbound:"uuid"`
	AlterID  int    `inbound:"alterId"`
}

func (o VmessOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Vmess struct {
	*Base
	config *VmessOption
	l      C.MultiAddrListener
	vs     LC.VmessServer
}

func NewVmess(options *VmessOption) (*Vmess, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users := make([]LC.VmessUser, len(options.Users))
	for i, v := range options.Users {
		users[i] = LC.VmessUser{
			Username: v.Username,
			UUID:     v.UUID,
			AlterID:  v.AlterID,
		}
	}
	return &Vmess{
		Base:   base,
		config: options,
		vs: LC.VmessServer{
			Enable:      true,
			Listen:      base.RawAddress(),
			Users:       users,
			WsPath:      options.WsPath,
			Certificate: options.Certificate,
			PrivateKey:  options.PrivateKey,
			MuxOption:   options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *Vmess) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *Vmess) Address() string {
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			return addr.String()
		}
	}
	return ""
}

// Listen implements constant.InboundListener
func (v *Vmess) Listen(tunnel C.Tunnel) error {
	var err error
	users := make([]LC.VmessUser, len(v.config.Users))
	for i, v := range v.config.Users {
		users[i] = LC.VmessUser{
			Username: v.Username,
			UUID:     v.UUID,
			AlterID:  v.AlterID,
		}
	}
	v.l, err = sing_vmess.New(v.vs, tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Vmess[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *Vmess) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*Vmess)(nil)
