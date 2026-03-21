package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type ShadowsocksServer struct {
	Enable    bool
	Listen    string
	Password  string
	Cipher    string
	Udp       bool
	MuxOption sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
	ShadowTLS ShadowTLS      `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	KcpTun    KcpTun         `yaml:"kcp-tun" json:"kcp-tun,omitempty"`
}

func (t ShadowsocksServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
