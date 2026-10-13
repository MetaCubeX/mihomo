package shadowsocks

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"

	"github.com/stretchr/testify/require"
)

// acceptTrackingListener signals once Accept has failed twice. A loopback
// listener only fails Accept after it is closed, so a second failure means
// the accept loop went back for another Accept after Close.
type acceptTrackingListener struct {
	net.Listener
	failures atomic.Int32
	spinning chan struct{}
}

func (l *acceptTrackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil && l.failures.Add(1) == 2 {
		close(l.spinning)
	}
	return c, err
}

type acceptTrackingListenConfig struct {
	C.InboundListenConfig
	listener *acceptTrackingListener
}

func (lc *acceptTrackingListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := lc.InboundListenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	lc.listener = &acceptTrackingListener{Listener: l, spinning: make(chan struct{})}
	return lc.listener, nil
}

func TestListenerCloseStopsAcceptLoop(t *testing.T) {
	lc := &acceptTrackingListenConfig{InboundListenConfig: inbound.NewListenConfig()}
	l, err := New(LC.ShadowsocksServer{
		Listen:   "127.0.0.1:0",
		Password: "password",
		Cipher:   "aes-128-ctr",
	}, lc, nil)
	require.NoError(t, err)
	require.NoError(t, l.Close())

	select {
	case <-lc.listener.spinning:
		t.Fatal("accept loop kept calling Accept after Close")
	case <-time.After(100 * time.Millisecond):
	}
}
