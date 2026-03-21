package inbound

import "github.com/metacubex/mihomo/listener/reality"

type RealityConfig struct {
	Dest              string   `inbound:"dest"`
	PrivateKey        string   `inbound:"private-key"`
	ShortID           []string `inbound:"short-id"`
	ServerNames       []string `inbound:"server-names"`
	MaxTimeDifference int      `inbound:"max-time-difference,omitempty"`
	Proxy             string   `inbound:"proxy,omitempty"`

	LimitFallbackUpload   RealityLimitFallback `inbound:"limit-fallback-upload,omitempty"`
	LimitFallbackDownload RealityLimitFallback `inbound:"limit-fallback-download,omitempty"`
}

type RealityLimitFallback struct {
	AfterBytes       uint64 `inbound:"after-bytes,omitempty"`
	BytesPerSec      uint64 `inbound:"bytes-per-sec,omitempty"`
	BurstBytesPerSec uint64 `inbound:"burst-bytes-per-sec,omitempty"`
}

func (c RealityConfig) Build() reality.Config {
	return reality.Config{
		Dest:              c.Dest,
		PrivateKey:        c.PrivateKey,
		ShortID:           c.ShortID,
		ServerNames:       c.ServerNames,
		MaxTimeDifference: c.MaxTimeDifference,
		Proxy:             c.Proxy,

		LimitFallbackUpload: reality.LimitFallback{
			AfterBytes:       c.LimitFallbackUpload.AfterBytes,
			BytesPerSec:      c.LimitFallbackUpload.BytesPerSec,
			BurstBytesPerSec: c.LimitFallbackUpload.BurstBytesPerSec,
		},
		LimitFallbackDownload: reality.LimitFallback{
			AfterBytes:       c.LimitFallbackDownload.AfterBytes,
			BytesPerSec:      c.LimitFallbackDownload.BytesPerSec,
			BurstBytesPerSec: c.LimitFallbackDownload.BurstBytesPerSec,
		},
	}
}
