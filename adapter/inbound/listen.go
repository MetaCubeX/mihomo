package inbound

import (
	"context"
	"net"

	"github.com/metacubex/tfo-go"
)

var (
	lc = tfo.ListenConfig{
		DisableTFO: true,
	}
)

func SetTfo(open bool) {
	lc.DisableTFO = !open
}

func SetMPTCP(open bool) {
	setMultiPathTCP(&lc.ListenConfig, open)
}

func ListenContext(ctx context.Context, network, address string) (net.Listener, error) {
	return lc.Listen(ctx, network, address)
}

func Listen(network, address string) (net.Listener, error) {
	return ListenContext(context.Background(), network, address)
}
