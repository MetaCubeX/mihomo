package config

import (
	"encoding/json"
)

type TrustTunnelServer struct {
	Enable               bool              `yaml:"enable" json:"enable"`
	Listen               string            `yaml:"listen" json:"listen"`
	Users                map[string]string `yaml:"users" json:"users,omitempty"`
	Certificate          string            `yaml:"certificate" json:"certificate"`
	PrivateKey           string            `yaml:"private-key" json:"private-key"`
	ClientAuthType       string            `yaml:"client-auth-type" json:"client-auth-type,omitempty"`
	ClientAuthCert       string            `yaml:"client-auth-cert" json:"client-auth-cert,omitempty"`
	EchKey               string            `yaml:"ech-key" json:"ech-key"`
	Network              []string          `yaml:"network" json:"network,omitempty"`
	CongestionController string            `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	CWND                 int               `yaml:"cwnd" json:"cwnd,omitempty"`
}

func (t TrustTunnelServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
