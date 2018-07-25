package config

import (
	C "github.com/Dreamacro/clash/constant"
)

type General struct {
	*Base
	Mode     Mode
	LogLevel C.LogLevel
}

type Base struct {
	Port       *int
	SocketPort *int
	AllowLan   *bool
}
