package sing

import (
	"context"
	"fmt"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type Dialer struct {
	t     C.Tunnel
	proxy string
}

func (d Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network %s", network)
	}
	return inner.HandleTcp(d.t, destination.String(), d.proxy)
}

func (d Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unsupported ListenPacket")
}

var _ N.Dialer = (*Dialer)(nil)

func NewDialer(t C.Tunnel, proxy string) (d *Dialer) {
	return &Dialer{t, proxy}
}
