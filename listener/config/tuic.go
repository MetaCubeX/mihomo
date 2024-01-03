package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type TuicServer struct {
	Enable                bool              `yaml:"enable" json:"enable"`
	Listen                string            `yaml:"listen" json:"listen"`
	Token                 []string          `yaml:"token" json:"token,omitempty"`
	Users                 map[string]string `yaml:"users" json:"users,omitempty"`
	Certificate           string            `yaml:"certificate" json:"certificate"`
	PrivateKey            string            `yaml:"private-key" json:"private-key"`
	CongestionController  string            `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	MaxIdleTime           int               `yaml:"max-idle-time" json:"max-idle-time,omitempty"`
	AuthenticationTimeout int               `yaml:"authentication-timeout" json:"authentication-timeout,omitempty"`
	ALPN                  []string          `yaml:"alpn" json:"alpn,omitempty"`
	MaxUdpRelayPacketSize int               `yaml:"max-udp-relay-packet-size" json:"max-udp-relay-packet-size,omitempty"`
	MaxDatagramFrameSize  int               `yaml:"max-datagram-frame-size" json:"max-datagram-frame-size,omitempty"`
	CWND                  int               `yaml:"cwnd" json:"cwnd,omitempty"`
	MuxOption             sing.MuxOption    `yaml:"mux-option" json:"mux-option,omitempty"`
}

func (t TuicServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
