package dialer

import "net"

type DialerHookFunc = func(*net.Dialer)
type ListenConfigHookFunc = func(*net.ListenConfig)

var (
	DialerHook       DialerHookFunc       = nil
	ListenConfigHook ListenConfigHookFunc = nil
)
