package inbound

import (
	LC "github.com/metacubex/mihomo/listener/config"
)

type ResTLS struct {
	Enable       bool   `inbound:"enable"`
	Dest         string `inbound:"dest"`
	Password     string `inbound:"password"`
	RestlsScript string `inbound:"restls-script,omitempty"`
	MinRecordLen int    `inbound:"min-record-len,omitempty"`
	RateLimit    uint64 `inbound:"rate-limit,omitempty"`
	Proxy        string `inbound:"proxy,omitempty"`
}

func (r ResTLS) Build() LC.ResTLS {
	return LC.ResTLS{
		Enable:       r.Enable,
		Dest:         r.Dest,
		Password:     r.Password,
		RestlsScript: r.RestlsScript,
		MinRecordLen: r.MinRecordLen,
		RateLimit:    r.RateLimit,
		Proxy:        r.Proxy,
	}
}
