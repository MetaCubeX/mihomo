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
}

func (t MiuServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
