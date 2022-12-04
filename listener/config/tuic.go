package config

import (
	"encoding/json"
)

type TuicServer struct {
	Enable                bool
	Listen                string
	Token                 []string
	Certificate           string
	PrivateKey            string
	CongestionController  string
	MaxIdleTime           int
	AuthenticationTimeout int
	ALPN                  []string
	MaxUdpRelayPacketSize int
}

func (t TuicServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
