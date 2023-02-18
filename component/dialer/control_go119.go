//go:build !go1.20

package dialer

import (
	"context"
	"net"
	"syscall"
)

func addControlToDialer(d *net.Dialer, fn controlFn) {
	ld := *d
	d.Control = func(network, address string, c syscall.RawConn) (err error) {
		switch {
		case ld.Control != nil:
			if err = ld.Control(network, address, c); err != nil {
				return
			}
		}
		return fn(context.Background(), network, address, c)
	}
}
