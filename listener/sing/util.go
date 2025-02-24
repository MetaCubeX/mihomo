package sing

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/transport/socks5"
)

// HandleSocket like inbound.NewSocket combine with Tunnel.HandleTCPConn but also handel specialFqdn
func (h *ListenerHandler) HandleSocket(target socks5.Addr, conn net.Conn, _additions ...inbound.Addition) {
	conn, metadata := inbound.NewSocket(target, conn, h.Type, h.Additions...)
	if h.IsSpecialFqdn(metadata.Host) {
		_ = h.ParseSpecialFqdn(
			WithAdditions(context.Background(), _additions...),
			conn,
			ConvertMetadata(metadata),
		)
	} else {
		inbound.ApplyAdditions(metadata, _additions...)
		h.Tunnel.HandleTCPConn(conn, metadata)
	}
}
