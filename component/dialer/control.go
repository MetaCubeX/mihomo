package dialer

import (
	"context"
	"net"
	"syscall"
)

type controlFn = func(ctx context.Context, network, address string, c syscall.RawConn) error

func addControlToListenConfig(lc *net.ListenConfig, fn controlFn) {
	llc := *lc
	lc.Control = func(network, address string, c syscall.RawConn) (err error) {
		switch {
		case llc.Control != nil:
			if err = llc.Control(network, address, c); err != nil {
				return
			}
		}
		return fn(context.Background(), network, address, c)
	}
}
