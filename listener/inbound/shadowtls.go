package inbound

import (
	"github.com/metacubex/mihomo/common/utils"
	LC "github.com/metacubex/mihomo/listener/config"
)

type ShadowTLS struct {
	Enable                 bool                                 `inbound:"enable"`
	Version                int                                  `inbound:"version,omitempty"`
	Password               string                               `inbound:"password,omitempty"`
	Users                  []ShadowTLSUser                      `inbound:"users,omitempty"`
	Handshake              ShadowTLSHandshakeOptions            `inbound:"handshake,omitempty"`
	HandshakeForServerName map[string]ShadowTLSHandshakeOptions `inbound:"handshake-for-server-name,omitempty"`
	StrictMode             bool                                 `inbound:"strict-mode,omitempty"`
	WildcardSNI            string                               `inbound:"wildcard-sni,omitempty"`
}

type ShadowTLSUser struct {
	Name     string `inbound:"name,omitempty"`
	Password string `inbound:"password,omitempty"`
}

type ShadowTLSHandshakeOptions struct {
	Dest  string `inbound:"dest"`
	Proxy string `inbound:"proxy,omitempty"`
}

func (c ShadowTLS) Build() LC.ShadowTLS {
	handshakeForServerName := make(map[string]LC.ShadowTLSHandshakeOptions)
	for k, v := range c.HandshakeForServerName {
		handshakeForServerName[k] = v.Build()
	}
	return LC.ShadowTLS{
		Enable:                 c.Enable,
		Version:                c.Version,
		Password:               c.Password,
		Users:                  utils.Map(c.Users, ShadowTLSUser.Build),
		Handshake:              c.Handshake.Build(),
		HandshakeForServerName: handshakeForServerName,
		StrictMode:             c.StrictMode,
		WildcardSNI:            c.WildcardSNI,
	}
}

func (c ShadowTLSUser) Build() LC.ShadowTLSUser {
	return LC.ShadowTLSUser{
		Name:     c.Name,
		Password: c.Password,
	}
}

func (c ShadowTLSHandshakeOptions) Build() LC.ShadowTLSHandshakeOptions {
	return LC.ShadowTLSHandshakeOptions{
		Dest:  c.Dest,
		Proxy: c.Proxy,
	}
}
