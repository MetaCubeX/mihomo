package outbound

// MuxCoolOptions is the options of Mux.Cool, the multiplexing protocol built in v2ray/xray.
// It only applies to TCP connections, UDP still uses its own connection (xudp/packetaddr).
type MuxCoolOptions struct {
	Enabled     bool `proxy:"enabled,omitempty"`
	Concurrency int  `proxy:"concurrency,omitempty"` // max sub connections in one connection, default 8
}
