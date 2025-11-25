package xhttp

import "time"

// Buffer and channel size constants
const (
	DefaultPacketChannelSize = 64
	DefaultReadBufferSize    = 32 * 1024
	DefaultMaxWriteSize      = 1024 * 1024
)

// Timeout and interval constants
const (
	DefaultPollInterval = 100 * time.Millisecond
	DefaultMaxPackets   = 30
)
