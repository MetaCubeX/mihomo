package config

import (
	"encoding/json"
)

type VmessUser struct {
	Username string
	UUID     string
	AlterID  int
}

type VmessServer struct {
	Enable bool
	Listen string
	Users  []VmessUser
	WsPath string
}

func (t VmessServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
