package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/hysteria2_realm"
	"github.com/metacubex/mihomo/log"
)

type Hysteria2RealmServerOption struct {
	BaseOption
	Token              string   `inbound:"token"`
	MaxRealms          int      `inbound:"max-realms,omitempty"`
	MaxRealmsPerIP     int      `inbound:"max-realms-per-ip,omitempty"`
	TrustedProxyHeader string   `inbound:"trusted-proxy-header,omitempty"`
	RealmNamePattern   string   `inbound:"realm-name-pattern,omitempty"`
	Certificate        string   `inbound:"certificate,omitempty"`
	PrivateKey         string   `inbound:"private-key,omitempty"`
	ClientAuthType     string   `inbound:"client-auth-type,omitempty"`
	ClientAuthCert     string   `inbound:"client-auth-cert,omitempty"`
	EchKey             string   `inbound:"ech-key,omitempty"`
	ALPN               []string `inbound:"alpn,omitempty"`
}

func (o Hysteria2RealmServerOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

func DefaultHysteria2RealmServerOption() *Hysteria2RealmServerOption {
	return &Hysteria2RealmServerOption{
		MaxRealms:        hysteria2_realm.DefaultMaxRealms,
		MaxRealmsPerIP:   hysteria2_realm.DefaultMaxRealmsPerIP,
		RealmNamePattern: hysteria2_realm.DefaultRealmNamePattern,
		ALPN:             hysteria2_realm.DefaultALPN(),
	}
}

type Hysteria2RealmServer struct {
	*Base
	config *Hysteria2RealmServerOption
	l      *hysteria2_realm.Listener
	ts     LC.Hysteria2RealmServer
}

func NewHysteria2RealmServer(options *Hysteria2RealmServerOption) (*Hysteria2RealmServer, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Hysteria2RealmServer{
		Base:   base,
		config: options,
		ts: LC.Hysteria2RealmServer{
			Enable:             true,
			Listen:             base.RawAddress(),
			Token:              options.Token,
			MaxRealms:          options.MaxRealms,
			MaxRealmsPerIP:     options.MaxRealmsPerIP,
			TrustedProxyHeader: options.TrustedProxyHeader,
			RealmNamePattern:   options.RealmNamePattern,
			Certificate:        options.Certificate,
			PrivateKey:         options.PrivateKey,
			ClientAuthType:     options.ClientAuthType,
			ClientAuthCert:     options.ClientAuthCert,
			EchKey:             options.EchKey,
			ALPN:               options.ALPN,
		},
	}, nil
}

// Config implements constant.InboundListener
func (t *Hysteria2RealmServer) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *Hysteria2RealmServer) Address() string {
	var addrList []string
	if t.l != nil {
		for _, addr := range t.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (t *Hysteria2RealmServer) Listen(tunnel C.Tunnel) error {
	var err error
	t.l, err = hysteria2_realm.New(t.ts, t.ListenConfig(), tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Hysteria2_Realm[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *Hysteria2RealmServer) Close() error {
	return t.l.Close()
}

var _ C.InboundListener = (*Hysteria2)(nil)
