package config

import "encoding/json"

type ResTLS struct {
	Enable       bool
	Dest         string
	Password     string
	RestlsScript string
	MinRecordLen int
	RateLimit    uint64
	Proxy        string
}

func (r ResTLS) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}
