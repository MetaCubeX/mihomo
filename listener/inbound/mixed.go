package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/log"
)

type MixedOption struct {
	BaseOption
	Users          AuthUsers     `inbound:"users,omitempty"`
	UDP            bool          `inbound:"udp,omitempty"`
	Certificate    string        `inbound:"certificate,omitempty"`
	PrivateKey     string        `inbound:"private-key,omitempty"`
	ClientAuthType string        `inbound:"client-auth-type,omitempty"`
	ClientAuthCert string        `inbound:"client-auth-cert,omitempty"`
	EchKey         string        `inbound:"ech-key,omitempty"`
	RealityConfig  RealityConfig `inbound:"reality-config,omitempty"`
}

func (o MixedOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Mixed struct {
	*Base
	config *MixedOption
	l      []*mixed.Listener
	lUDP   []*socks.UDPListener
	udp    bool
}

func NewMixed(options *MixedOption) (*Mixed, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Mixed{
		Base:   base,
		config: options,
		udp:    options.UDP,
	}, nil
}

// Config implements constant.InboundListener
func (m *Mixed) Config() C.InboundConfig {
	return m.config
}

// Address implements constant.InboundListener
func (m *Mixed) Address() string {
	var addrList []string
	for _, l := range m.l {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (m *Mixed) Listen(tunnel C.Tunnel) error {
	for _, addr := range strings.Split(m.RawAddress(), ",") {
		l, err := mixed.NewWithConfig(
			LC.AuthServer{
				Enable:         true,
				Listen:         addr,
				AuthStore:      m.config.Users.GetAuthStore(),
				Certificate:    m.config.Certificate,
				PrivateKey:     m.config.PrivateKey,
				ClientAuthType: m.config.ClientAuthType,
				ClientAuthCert: m.config.ClientAuthCert,
				EchKey:         m.config.EchKey,
				RealityConfig:  m.config.RealityConfig.Build(),
			},
			tunnel,
			m.Additions()...,
		)
		if err != nil {
			return err
		}
		m.l = append(m.l, l)
		if m.udp {
			lUDP, err := socks.NewUDP(addr, tunnel, m.Additions()...)
			if err != nil {
				return err
			}
			m.lUDP = append(m.lUDP, lUDP)
		}
	}
	log.Infoln("Mixed(http+socks)[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

// Close implements constant.InboundListener
func (m *Mixed) Close() error {
	var errs []error
	for _, l := range m.l {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close tcp listener %s err: %w", l.Address(), err))
		}
	}
	for _, l := range m.lUDP {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close udp listener %s err: %w", l.Address(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*Mixed)(nil)
