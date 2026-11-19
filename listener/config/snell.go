package config

import "encoding/json"

type SnellServer struct {
	Listen    string
	Psk       string
	Version   int
	Mode      string // v6 only: default / unshaped / unsafe-raw
	UDP       bool
	ObfsMode  string
	ObfsHost  string
	ShadowTLS ShadowTLS `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS    ResTLS    `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig JLSConfig `yaml:"jls-config" json:"jls-config,omitempty"`
}

func (c SnellServer) String() string {
	b, _ := json.Marshal(c)
	return string(b)
}
