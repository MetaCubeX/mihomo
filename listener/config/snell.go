package config

import "encoding/json"

type SnellServer struct {
	Listen   string
	Psk      string
	Version  int
	UDP      bool
	ObfsMode string
	ObfsHost string
}

func (c SnellServer) String() string {
	b, _ := json.Marshal(c)
	return string(b)
}
