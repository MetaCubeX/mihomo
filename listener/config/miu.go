package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/reality"
)

type MiuServer struct {
	Enable         bool              `yaml:"enable" json:"enable"`
	Listen         string            `yaml:"listen" json:"listen"`
	Users          map[string]string `yaml:"users" json:"users,omitempty"`
	Certificate    string            `yaml:"certificate" json:"certificate,omitempty"`
	PrivateKey     string            `yaml:"private-key" json:"private-key,omitempty"`
	ClientAuthType string            `yaml:"client-auth-type" json:"client-auth-type,omitempty"`
	ClientAuthCert string            `yaml:"client-auth-cert" json:"client-auth-cert,omitempty"`
	EchKey         string            `yaml:"ech-key" json:"ech-key,omitempty"`
	RealityConfig  reality.Config    `yaml:"reality-config" json:"reality-config,omitempty"`
	PaddingScheme  string            `yaml:"padding-scheme" json:"padding-scheme,omitempty"`
	// Fallback (certificate mode) is host:port of a web server that gets every connection that is not
	// a client, so that it is answered as that web server answers it.
	Fallback string `yaml:"fallback" json:"fallback,omitempty"`
	// ALPN (certificate mode) is what the outer TLS offers to negotiate; default ["http/1.1"]. Offer
	// only what the fallback speaks.
	ALPN []string `yaml:"alpn" json:"alpn,omitempty"`
}

func (t MiuServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
