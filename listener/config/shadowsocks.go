package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type ShadowsocksServer struct {
	Enable     bool
	Listen     string
	Password   string
	Users      map[string]string `yaml:"users" json:"users,omitempty"`
	Cipher     string
	Udp        bool
	MuxOption  sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
	ShadowTLS  ShadowTLS      `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS     ResTLS         `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig  JLSConfig      `yaml:"jls-config" json:"jls-config,omitempty"`
	KcpTun     KcpTun         `yaml:"kcp-tun" json:"kcp-tun,omitempty"`
	SimpleObfs SimpleObfs     `yaml:"simple-obfs" json:"simple-obfs,omitempty"`
}

type SimpleObfs struct {
	Enable bool
	Mode   string
}

func (t ShadowsocksServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
