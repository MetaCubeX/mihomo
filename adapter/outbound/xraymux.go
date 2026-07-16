package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/xraymux"
)

const (
	xrayMuxDestination = "v1.mux.cool"
	xrayMuxPort        = 9527

	xudpProxyUDP443Reject = "reject"
	xudpProxyUDP443Allow  = "allow"
	xudpProxyUDP443Skip   = "skip"
)

var ErrXrayMuxUDP443Rejected = errors.New("xray mux rejected UDP/443 traffic")

type XrayMuxOption struct {
	Enabled         bool   `proxy:"enabled,omitempty"`
	MaxConcurrency  int    `proxy:"max-concurrency,omitempty"`
	MaxConnections  int    `proxy:"max-connections,omitempty"`
	XUDPConcurrency int    `proxy:"xudp-concurrency,omitempty"`
	XUDPProxyUDP443 string `proxy:"xudp-proxy-udp443,omitempty"`
}

type XrayMux struct {
	ProxyAdapter
	pool      *xraymux.Pool
	xudpPool  *xraymux.Pool
	option    XrayMuxOption
	closeOnce sync.Once
	closeErr  error
}

func NewXrayMux(option XrayMuxOption, proxy ProxyAdapter) (ProxyAdapter, error) {
	if option.MaxConcurrency < 0 {
		return nil, fmt.Errorf("xray-mux max-concurrency must not be negative")
	}
	if option.MaxConnections < 0 {
		return nil, fmt.Errorf("xray-mux max-connections must not be negative")
	}
	if option.XUDPConcurrency < 0 {
		return nil, fmt.Errorf("xray-mux xudp-concurrency must not be negative")
	}
	switch option.XUDPProxyUDP443 {
	case "":
		option.XUDPProxyUDP443 = xudpProxyUDP443Reject
	case xudpProxyUDP443Reject, xudpProxyUDP443Allow, xudpProxyUDP443Skip:
	default:
		return nil, fmt.Errorf("xray-mux xudp-proxy-udp443 must be reject, allow, or skip")
	}
	if option.MaxConcurrency == 0 {
		option.MaxConcurrency = xraymux.DefaultMaxConcurrency
	}
	if option.MaxConnections == 0 {
		option.MaxConnections = xraymux.DefaultMaxConnections
	}

	wrapper := &XrayMux{ProxyAdapter: proxy, option: option}
	wrapper.pool = wrapper.newPool(option.MaxConcurrency)
	if option.XUDPConcurrency > 0 {
		wrapper.xudpPool = wrapper.newPool(option.XUDPConcurrency)
	}
	return wrapper, nil
}

func (x *XrayMux) newPool(maxConcurrency int) *xraymux.Pool {
	return xraymux.NewPool(x.dialCarrier, xraymux.Options{
		MaxConcurrency: maxConcurrency,
		MaxConnections: x.option.MaxConnections,
	})
}

func (x *XrayMux) Options() XrayMuxOption {
	return x.option
}

func (x *XrayMux) dialCarrier(ctx context.Context) (net.Conn, error) {
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.INNER,
		Host:    xrayMuxDestination,
		DstPort: xrayMuxPort,
	}
	return x.ProxyAdapter.DialContext(ctx, metadata)
}

func (x *XrayMux) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if metadata.NetWork != C.TCP {
		return x.ProxyAdapter.DialContext(ctx, metadata)
	}
	conn, err := x.pool.DialContext(ctx, metadata.String(), metadata.DstPort)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, x), nil
}

func (x *XrayMux) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if metadata.DstPort == 443 {
		switch x.option.XUDPProxyUDP443 {
		case xudpProxyUDP443Reject:
			return nil, ErrXrayMuxUDP443Rejected
		case xudpProxyUDP443Skip:
			return x.ProxyAdapter.ListenPacketContext(ctx, metadata)
		}
	}

	var globalID [8]byte
	if metadata.SourceValid() {
		globalID = utils.GlobalID(metadata.SourceAddress())
	}
	pool := x.pool
	if x.xudpPool != nil {
		pool = x.xudpPool
	}
	packetConn, err := pool.ListenPacketContext(ctx, metadata.String(), metadata.DstPort, globalID)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(packetConn, x), nil
}

func (x *XrayMux) SupportUDP() bool {
	return true
}

func (x *XrayMux) SupportUOT() bool {
	return true
}

func (x *XrayMux) ProxyInfo() C.ProxyInfo {
	info := x.ProxyAdapter.ProxyInfo()
	info.XUDP = true
	return info
}

func (x *XrayMux) Close() error {
	x.closeOnce.Do(func() {
		if x.xudpPool != nil {
			_ = x.xudpPool.Close()
		}
		_ = x.pool.Close()
		x.closeErr = x.ProxyAdapter.Close()
	})
	return x.closeErr
}
