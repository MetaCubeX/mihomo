package dialer

import (
	"context"
	"net"
)

func Dialer() *net.Dialer {
	dialer := &net.Dialer{}
	if DialerHook != nil {
		DialerHook(dialer)
	}

	return dialer
}

func ListenConfig() *net.ListenConfig {
	cfg := &net.ListenConfig{}
	if ListenConfigHook != nil {
		ListenConfigHook(cfg)
	}

	return cfg
}

func Dial(network, address string) (net.Conn, error) {
	return DialContext(context.Background(), network, address)
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dailer := Dialer()
	return dailer.DialContext(ctx, network, address)
}

func ListenPacket(network, address string) (net.PacketConn, error) {
	lc := ListenConfig()
	return lc.ListenPacket(context.Background(), network, address)
}
