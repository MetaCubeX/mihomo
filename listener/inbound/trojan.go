package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/trojan"
	"github.com/metacubex/mihomo/log"
)

type TrojanOption struct {
	BaseOption
	Users           []TrojanUser   `inbound:"users"`
	WsPath          string         `inbound:"ws-path,omitempty"`
	GrpcServiceName string         `inbound:"grpc-service-name,omitempty"`
	Certificate     string         `inbound:"certificate,omitempty"`
	PrivateKey      string         `inbound:"private-key,omitempty"`
	ClientAuthType  string         `inbound:"client-auth-type,omitempty"`
	ClientAuthCert  string         `inbound:"client-auth-cert,omitempty"`
	EchKey          string         `inbound:"ech-key,omitempty"`
	RealityConfig   RealityConfig  `inbound:"reality-config,omitempty"`
	MuxOption       MuxOption      `inbound:"mux-option,omitempty"`
	SSOption        TrojanSSOption `inbound:"ss-option,omitempty"`
}

type TrojanUser struct {
	Username string `inbound:"username,omitempty"`
	Password string `inbound:"password"`
}

// TrojanSSOption from https://github.com/p4gefau1t/trojan-go/blob/v0.10.6/tunnel/shadowsocks/config.go#L5
type TrojanSSOption struct {
	Enabled  bool   `inbound:"enabled,omitempty"`
	Method   string `inbound:"method,omitempty"`
	Password string `inbound:"password,omitempty"`
}

func (o TrojanOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Trojan struct {
	*Base
	config *TrojanOption
	l      C.MultiAddrListener
	vs     LC.TrojanServer
}

func NewTrojan(options *TrojanOption) (*Trojan, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users := make([]LC.TrojanUser, len(options.Users))
	for i, v := range options.Users {
		users[i] = LC.TrojanUser{
			Username: v.Username,
			Password: v.Password,
		}
	}
	return &Trojan{
		Base:   base,
		config: options,
		vs: LC.TrojanServer{
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
			RealityConfig:   options.RealityConfig.Build(),
			MuxOption:       options.MuxOption.Build(),
			TrojanSSOption: LC.TrojanSSOption{
				Enabled:  options.SSOption.Enabled,
				Method:   options.SSOption.Method,
				Password: options.SSOption.Password,
			},
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *Trojan) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *Trojan) Address() string {
	var addrList []string
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (v *Trojan) Listen(tunnel C.Tunnel) error {
	var err error
	v.l, err = trojan.New(v.vs, tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Trojan[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *Trojan) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*Trojan)(nil)
