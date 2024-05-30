package inbound

import (
	"context"
	"net"
)

func SetMPTCP(open bool) {
	setMultiPathTCP(getListenConfig(), open)
}

func ListenContext(ctx context.Context, network, address string) (net.Listener, error) {
	return lc.Listen(ctx, network, address)
}

func Listen(network, address string) (net.Listener, error) {
	return ListenContext(context.Background(), network, address)
}
