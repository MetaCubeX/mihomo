package inbound

import "github.com/metacubex/mihomo/listener/reality"

type RealityConfig struct {
	Target            string   `inbound:"target,omitempty"`
	Dest              string   `inbound:"dest"`
	Type              string   `inbound:"type,omitempty"`
	Xver              uint64   `inbound:"xver,omitempty"`
	PrivateKey        string   `inbound:"private-key"`
	ShortID           []string `inbound:"short-id"`
	ServerNames       []string `inbound:"server-names"`
	MinClientVersion  string   `inbound:"min-client-ver,omitempty"`
	MaxClientVersion  string   `inbound:"max-client-ver,omitempty"`
	MaxTimeDifference int      `inbound:"max-time-difference,omitempty"`
	Mldsa65Seed       string   `inbound:"mldsa65-seed,omitempty"`
	Show              bool     `inbound:"show,omitempty"`
	MasterKeyLog      string   `inbound:"master-key-log,omitempty"`
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
		Target:            c.Target,
		Dest:              c.Dest,
		Type:              c.Type,
		Xver:              c.Xver,
		PrivateKey:        c.PrivateKey,
		ShortID:           c.ShortID,
		ServerNames:       c.ServerNames,
		MinClientVersion:  c.MinClientVersion,
		MaxClientVersion:  c.MaxClientVersion,
		MaxTimeDifference: c.MaxTimeDifference,
		Mldsa65Seed:       c.Mldsa65Seed,
		Show:              c.Show,
		MasterKeyLog:      c.MasterKeyLog,
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
