//go:build !with_gvisor

package sing_tun

import (
	"context"
	"net"

	M "github.com/metacubex/sing/common/metadata"
)

func (h *ListenerHandler) handleTCPConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return h.ListenerHandler.NewConnection(ctx, conn, metadata)
}
