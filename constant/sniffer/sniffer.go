package sniffer

import "github.com/Dreamacro/clash/constant"

type Sniffer interface {
	SupportNetwork() constant.NetWork
	SniffTCP(bytes []byte) (string, error)
	Protocol() string
	SupportPort(port uint16) bool
}

const (
	TLS Type = iota
	HTTP
)

var (
	List = []Type{TLS, HTTP}
)

type Type int

func (rt Type) String() string {
	switch rt {
	case TLS:
		return "TLS"
	case HTTP:
		return "HTTP"
	default:
		return "Unknown"
	}
}
