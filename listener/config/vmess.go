package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type VmessUser struct {
	Username string
	UUID     string
	AlterID  int
}

type VmessServer struct {
	Enable      bool
	Listen      string
	Users       []VmessUser
	WsPath      string
	Certificate string
	PrivateKey  string
	MuxOption   sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
}

func (t VmessServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
