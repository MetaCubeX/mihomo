package inbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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

func preResolve(network, address string) (string, error) {
	switch network { // like net.Resolver.internetAddrList but filter domain to avoid call net.Resolver.lookupIPAddr
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip", "ip4", "ip6":
		if host, port, err := net.SplitHostPort(address); err == nil {
			switch host {
			case "localhost":
				switch network {
				case "tcp6", "udp6", "ip6":
					address = net.JoinHostPort("::1", port)
				default:
					address = net.JoinHostPort("127.0.0.1", port)
				}
			case "": // internetAddrList can handle this special case
				break
			default:
				if _, err := netip.ParseAddr(host); err != nil { // not ip
					return "", fmt.Errorf("invalid network address: %s", address)
				}
			}
		}
	}
	return address, nil
}

func ListenContext(ctx context.Context, network, address string) (net.Listener, error) {
	address, err := preResolve(network, address)
	if err != nil {
		return nil, err
	}

	mutex.RLock()
	defer mutex.RUnlock()
	return lc.Listen(ctx, network, address)
}

func Listen(network, address string) (net.Listener, error) {
	return ListenContext(context.Background(), network, address)
}

func ListenPacketContext(ctx context.Context, network, address string) (net.PacketConn, error) {
	address, err := preResolve(network, address)
	if err != nil {
		return nil, err
	}

	mutex.RLock()
	defer mutex.RUnlock()
	return lc.ListenPacket(ctx, network, address)
}

func ListenPacket(network, address string) (net.PacketConn, error) {
	return ListenPacketContext(context.Background(), network, address)
}

func init() {
	keepalive.SetDisableKeepAliveCallback.Register(func(b bool) {
		mutex.Lock()
		defer mutex.Unlock()
		keepalive.SetNetListenConfig(&lc.ListenConfig)
	})
}
