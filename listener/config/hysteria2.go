package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type Hysteria2Server struct {
	Enable                bool              `yaml:"enable" json:"enable"`
	Listen                string            `yaml:"listen" json:"listen"`
	Users                 map[string]string `yaml:"users" json:"users,omitempty"`
	Obfs                  string            `yaml:"obfs" json:"obfs,omitempty"`
	ObfsPassword          string            `yaml:"obfs-password" json:"obfs-password,omitempty"`
	Certificate           string            `yaml:"certificate" json:"certificate"`
	PrivateKey            string            `yaml:"private-key" json:"private-key"`
	MaxIdleTime           int               `yaml:"max-idle-time" json:"max-idle-time,omitempty"`
	ALPN                  []string          `yaml:"alpn" json:"alpn,omitempty"`
	Up                    string            `yaml:"up" json:"up,omitempty"`
	Down                  string            `yaml:"down" json:"down,omitempty"`
	IgnoreClientBandwidth bool              `yaml:"ignore-client-bandwidth" json:"ignore-client-bandwidth,omitempty"`
	Masquerade            string            `yaml:"masquerade" json:"masquerade,omitempty"`
	CWND                  int               `yaml:"cwnd" json:"cwnd,omitempty"`
	UdpMTU                int               `yaml:"udp-mtu" json:"udp-mtu,omitempty"`
	MuxOption             sing.MuxOption    `yaml:"mux-option" json:"mux-option,omitempty"`
}

func (h Hysteria2Server) String() string {
	b, _ := json.Marshal(h)
	return string(b)
}
