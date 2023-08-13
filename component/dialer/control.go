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

func addControlToDialer(d *net.Dialer, fn controlFn) {
	ld := *d
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		switch {
		case ld.ControlContext != nil:
			if err = ld.ControlContext(ctx, network, address, c); err != nil {
				return
			}
		case ld.Control != nil:
			if err = ld.Control(network, address, c); err != nil {
				return
			}
		}
		return fn(ctx, network, address, c)
	}
}
