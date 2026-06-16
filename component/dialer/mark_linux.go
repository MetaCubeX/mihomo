//go:build linux

package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/mihomo/common/sockopt"
)

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	addControlToDialer(dialer, bindMarkToControl(mark))
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, _ string) {
	addControlToListenConfig(lc, bindMarkToControl(mark))
}

func bindMarkToControl(mark int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		return sockopt.RawConnMark(c, mark)
	}
}
