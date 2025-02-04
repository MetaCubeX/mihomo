package inbound

import "github.com/metacubex/mihomo/listener/reality"

type RealityConfig struct {
	Dest              string   `inbound:"dest"`
	PrivateKey        string   `inbound:"private-key"`
	ShortID           []string `inbound:"short-id"`
	ServerNames       []string `inbound:"server-names"`
	MaxTimeDifference int      `inbound:"max-time-difference,omitempty"`
	Proxy             string   `inbound:"proxy,omitempty"`
}

func (c RealityConfig) Build() reality.Config {
	return reality.Config{
		Dest:              c.Dest,
		PrivateKey:        c.PrivateKey,
		ShortID:           c.ShortID,
		ServerNames:       c.ServerNames,
		MaxTimeDifference: c.MaxTimeDifference,
		Proxy:             c.Proxy,
	}
}
