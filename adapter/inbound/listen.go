package inbound

import (
	"context"
	"net"
	"sync"

	"github.com/metacubex/mihomo/component/keepalive"

	"github.com/metacubex/tfo-go"
)

var (
	lc = tfo.ListenConfig{
		DisableTFO: true,
	}
	mutex sync.RWMutex
)

func SetTfo(open bool) {
	mutex.Lock()
	defer mutex.Unlock()
	lc.DisableTFO = !open
}

func Tfo() bool {
	mutex.RLock()
	defer mutex.RUnlock()
	return !lc.DisableTFO
}

func SetMPTCP(open bool) {
	mutex.Lock()
	defer mutex.Unlock()
	setMultiPathTCP(&lc.ListenConfig, open)
}

func MPTCP() bool {
	mutex.RLock()
	defer mutex.RUnlock()
	return getMultiPathTCP(&lc.ListenConfig)
}

func ListenContext(ctx context.Context, network, address string) (net.Listener, error) {
	mutex.RLock()
	defer mutex.RUnlock()
	return lc.Listen(ctx, network, address)
}

func Listen(network, address string) (net.Listener, error) {
	return ListenContext(context.Background(), network, address)
}

func init() {
	keepalive.SetDisableKeepAliveCallback.Register(func(b bool) {
		mutex.Lock()
		defer mutex.Unlock()
		keepalive.SetNetListenConfig(&lc.ListenConfig)
	})
}
