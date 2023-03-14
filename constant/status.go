package constant

type TunnelStatus uint8

const (
	TunnelSuspend TunnelStatus = iota
	TunnelInner
	TunnelRunning
)
