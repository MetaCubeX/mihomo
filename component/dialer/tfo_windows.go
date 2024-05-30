package dialer

import (
	"context"
	"net"
)

const DisableTFO = true

func dialTFO(ctx context.Context, netDialer net.Dialer, network, address string) (net.Conn, error) {
	return netDialer.DialContext(ctx, network, address)
}
