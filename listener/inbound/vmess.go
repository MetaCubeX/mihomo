package inbound

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/log"
)

type VmessOption struct {
	BaseOption
	Users           []VmessUser     `inbound:"users"`
	WsPath          string          `inbound:"ws-path,omitempty"`
	GrpcServiceName string          `inbound:"grpc-service-name,omitempty"`
	Certificate     string          `inbound:"certificate,omitempty"`
	PrivateKey      string          `inbound:"private-key,omitempty"`
	ClientAuthType  string          `inbound:"client-auth-type,omitempty"`
	ClientAuthCert  string          `inbound:"client-auth-cert,omitempty"`
	EchKey          string          `inbound:"ech-key,omitempty"`
	ShadowTLS       ShadowTLS       `inbound:"shadow-tls,omitempty"`
	ResTLS          ResTLS          `inbound:"res-tls,omitempty"`
	JLSConfig       JLSConfig       `inbound:"jls-config,omitempty"`
	RealityConfig   RealityConfig   `inbound:"reality-config,omitempty"`
	TLSMirrorConfig TLSMirrorConfig `inbound:"tlsmirror-config,omitempty"`
	MekyaConfig     MekyaConfig     `inbound:"mekya-config,omitempty"`
	MKCPConfig      MKCPConfig      `inbound:"mkcp-config,omitempty"`
	MuxOption       MuxOption       `inbound:"mux-option,omitempty"`
}

type VmessUser struct {
	Username string `inbound:"username,omitempty"`
	UUID     string `inbound:"uuid"`
	AlterID  int    `inbound:"alterId,omitempty"`
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
	base, err := newBase(&options.BaseOption, true)
	if err != nil {
		return nil, err
	}
	if base.unixSocket != "" && options.MKCPConfig.Enable {
		return nil, fmt.Errorf("mkcp cannot be used with a unix socket")
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
			Enable:          true,
			Listen:          base.RawAddress(),
			Users:           users,
			WsPath:          options.WsPath,
			GrpcServiceName: options.GrpcServiceName,
			Certificate:     options.Certificate,
			PrivateKey:      options.PrivateKey,
			ClientAuthType:  options.ClientAuthType,
			ClientAuthCert:  options.ClientAuthCert,
			EchKey:          options.EchKey,
			ShadowTLS:       options.ShadowTLS.Build(),
			ResTLS:          options.ResTLS.Build(),
			JLSConfig:       options.JLSConfig.Build(),
			RealityConfig:   options.RealityConfig.Build(),
			TLSMirrorConfig: options.TLSMirrorConfig.Build(),
			MekyaConfig:     options.MekyaConfig.Build(),
			MKCPConfig:      options.MKCPConfig.Build(),
			MuxOption:       options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *Vmess) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *Vmess) Address() string {
	var addrList []string
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (v *Vmess) Listen(tunnel C.Tunnel) error {
	var err error
	v.l, err = sing_vmess.New(v.vs, v.ListenConfig(), tunnel, v.Additions()...)
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
