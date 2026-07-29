package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/sing"
)

type ShadowQuicUser struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type ShadowQuicJLSUpstream struct {
	Addr      string `yaml:"addr" json:"addr"`
	SNI       string `yaml:"sni" json:"sni,omitempty"`
	Proxy     string `yaml:"proxy" json:"proxy,omitempty"`
	RateLimit uint64 `yaml:"rate-limit" json:"rate-limit,omitempty"`
}

type ShadowQuicServer struct {
	Enable                bool                  `yaml:"enable" json:"enable"`
	Listen                string                `yaml:"listen" json:"listen"`
	Users                 []ShadowQuicUser      `yaml:"users" json:"users,omitempty"`
	JLSUpstream           ShadowQuicJLSUpstream `yaml:"jls-upstream" json:"jls-upstream"`
	ALPN                  []string              `yaml:"alpn" json:"alpn,omitempty"`
	QUICVersions          []string              `yaml:"quic-versions" json:"quic-versions,omitempty"`
	ZeroRTT               bool                  `yaml:"zero-rtt" json:"zero-rtt,omitempty"`
	CongestionController  string                `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	Up                    string                `yaml:"up" json:"up,omitempty"`
	Down                  string                `yaml:"down" json:"down,omitempty"`
	IgnoreClientBandwidth bool                  `yaml:"ignore-client-bandwidth" json:"ignore-client-bandwidth,omitempty"`
	MaxIdleTime           int                   `yaml:"max-idle-time" json:"max-idle-time,omitempty"`
	MaxDatagramFrameSize  int                   `yaml:"max-datagram-frame-size" json:"max-datagram-frame-size,omitempty"`
	ReceiveWindowConn     int                   `yaml:"recv-window-conn" json:"recv-window-conn,omitempty"`
	ReceiveWindow         int                   `yaml:"recv-window" json:"recv-window,omitempty"`
	DisableMTUDiscovery   bool                  `yaml:"disable-mtu-discovery" json:"disable-mtu-discovery,omitempty"`
	CWND                  int                   `yaml:"cwnd" json:"cwnd,omitempty"`
	BBRProfile            string                `yaml:"bbr-profile" json:"bbr-profile,omitempty"`
	MuxOption             sing.MuxOption        `yaml:"mux-option" json:"mux-option,omitempty"`
}

func (s ShadowQuicServer) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}
