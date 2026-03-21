package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
)

type TrojanUser struct {
	Username string
	Password string
}

type TrojanServer struct {
	Enable          bool
	Listen          string
	Users           []TrojanUser
	WsPath          string
	GrpcServiceName string
	Certificate     string
	PrivateKey      string
	ClientAuthType  string
	ClientAuthCert  string
	EchKey          string
	RealityConfig   reality.Config
	MuxOption       sing.MuxOption
	TrojanSSOption  TrojanSSOption
}

// TrojanSSOption from https://github.com/p4gefau1t/trojan-go/blob/v0.10.6/tunnel/shadowsocks/config.go#L5
type TrojanSSOption struct {
	Enabled  bool
	Method   string
	Password string
}

func (t TrojanServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
