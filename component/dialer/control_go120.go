//go:build go1.20

package dialer

import (
	"context"
	"net"
	"syscall"
)

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
