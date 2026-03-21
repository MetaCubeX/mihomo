package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/trusttunnel"
	"github.com/metacubex/mihomo/log"
)

type TrustTunnelOption struct {
	BaseOption
	Users                AuthUsers `inbound:"users,omitempty"`
	Certificate          string    `inbound:"certificate"`
	PrivateKey           string    `inbound:"private-key"`
	ClientAuthType       string    `inbound:"client-auth-type,omitempty"`
	ClientAuthCert       string    `inbound:"client-auth-cert,omitempty"`
	EchKey               string    `inbound:"ech-key,omitempty"`
	Network              []string  `inbound:"network,omitempty"`
	CongestionController string    `inbound:"congestion-controller,omitempty"`
	CWND                 int       `inbound:"cwnd,omitempty"`
}

func (o TrustTunnelOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type TrustTunnel struct {
	*Base
	config *TrustTunnelOption
	l      C.MultiAddrListener
	vs     LC.TrustTunnelServer
}

func NewTrustTunnel(options *TrustTunnelOption) (*TrustTunnel, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users := make(map[string]string)
	for _, user := range options.Users {
		users[user.Username] = user.Password
	}
	return &TrustTunnel{
		Base:   base,
		config: options,
		vs: LC.TrustTunnelServer{
			Enable:               true,
			Listen:               base.RawAddress(),
			Users:                users,
			Certificate:          options.Certificate,
			PrivateKey:           options.PrivateKey,
			ClientAuthType:       options.ClientAuthType,
			ClientAuthCert:       options.ClientAuthCert,
			EchKey:               options.EchKey,
			Network:              options.Network,
			CongestionController: options.CongestionController,
			CWND:                 options.CWND,
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *TrustTunnel) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *TrustTunnel) Address() string {
	var addrList []string
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (v *TrustTunnel) Listen(tunnel C.Tunnel) error {
	var err error
	v.l, err = trusttunnel.New(v.vs, tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("TrustTunnel[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *TrustTunnel) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*TrustTunnel)(nil)
