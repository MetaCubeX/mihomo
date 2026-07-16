package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/muxcool"
)

const (
	muxCoolDestination = "v1.mux.cool"
	muxCoolPort        = 9527

	xudpProxyUDP443Reject = "reject"
	xudpProxyUDP443Allow  = "allow"
	xudpProxyUDP443Skip   = "skip"
)

var ErrMuxCoolUDP443Rejected = errors.New("mux.cool rejected UDP/443 traffic")

type MuxCoolOption struct {
	Enabled         bool   `proxy:"enabled,omitempty"`
	MaxConcurrency  int    `proxy:"max-concurrency,omitempty"`
	MaxConnections  int    `proxy:"max-connections,omitempty"`
	MaxCarriers     int    `proxy:"max-carriers,omitempty"`
	XUDPConcurrency int    `proxy:"xudp-concurrency,omitempty"`
	XUDPProxyUDP443 string `proxy:"xudp-proxy-udp443,omitempty"`
}

type MuxCool struct {
	ProxyAdapter
	pool      *muxcool.Pool
	xudpPool  *muxcool.Pool
	option    MuxCoolOption
	closeOnce sync.Once
	closeErr  error
}

func NewMuxCool(option MuxCoolOption, proxy ProxyAdapter) (ProxyAdapter, error) {
	if option.MaxConcurrency < 0 {
		return nil, fmt.Errorf("mux.cool max-concurrency must not be negative")
	}
	if option.MaxConnections < 0 {
		return nil, fmt.Errorf("mux.cool max-connections must not be negative")
	}
	if option.MaxCarriers < 0 {
		return nil, fmt.Errorf("mux.cool max-carriers must not be negative")
	}
	if option.XUDPConcurrency < 0 {
		return nil, fmt.Errorf("mux.cool xudp-concurrency must not be negative")
	}
	switch option.XUDPProxyUDP443 {
	case "":
		option.XUDPProxyUDP443 = xudpProxyUDP443Reject
	case xudpProxyUDP443Reject, xudpProxyUDP443Allow, xudpProxyUDP443Skip:
	default:
		return nil, fmt.Errorf("mux.cool xudp-proxy-udp443 must be reject, allow, or skip")
	}
	if option.MaxConcurrency == 0 {
		option.MaxConcurrency = muxcool.DefaultMaxConcurrency
	}
	if option.MaxConnections == 0 {
		option.MaxConnections = muxcool.DefaultMaxConnections
	}

	wrapper := &MuxCool{ProxyAdapter: proxy, option: option}
	var limiter *muxcool.CarrierLimiter
	if option.MaxCarriers > 0 {
		limiter = muxcool.NewCarrierLimiter(option.MaxCarriers)
	}
	wrapper.pool = wrapper.newPool(option.MaxConcurrency, limiter)
	if option.XUDPConcurrency > 0 {
		wrapper.xudpPool = wrapper.newPool(option.XUDPConcurrency, limiter)
	}
	return wrapper, nil
}

func (x *MuxCool) newPool(maxConcurrency int, limiter *muxcool.CarrierLimiter) *muxcool.Pool {
	return muxcool.NewPool(x.dialCarrier, muxcool.Options{
		MaxConcurrency: maxConcurrency,
		MaxConnections: x.option.MaxConnections,
		CarrierLimiter: limiter,
	})
}

func (x *MuxCool) Options() MuxCoolOption {
	return x.option
}

func (x *MuxCool) dialCarrier(ctx context.Context) (net.Conn, error) {
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.INNER,
		Host:    muxCoolDestination,
		DstPort: muxCoolPort,
	}
	return x.ProxyAdapter.DialContext(ctx, metadata)
}

func (x *MuxCool) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if metadata.NetWork != C.TCP {
		return x.ProxyAdapter.DialContext(ctx, metadata)
	}
	conn, err := x.pool.DialContext(ctx, metadata.String(), metadata.DstPort)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, x), nil
}

func (x *MuxCool) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if metadata.DstPort == 443 {
		switch x.option.XUDPProxyUDP443 {
		case xudpProxyUDP443Reject:
			return nil, ErrMuxCoolUDP443Rejected
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

func (x *MuxCool) SupportUDP() bool {
	return true
}

func (x *MuxCool) SupportUOT() bool {
	return true
}

func (x *MuxCool) ProxyInfo() C.ProxyInfo {
	info := x.ProxyAdapter.ProxyInfo()
	info.XUDP = true
	return info
}

func (x *MuxCool) Close() error {
	x.closeOnce.Do(func() {
		if x.xudpPool != nil {
			_ = x.xudpPool.Close()
		}
		_ = x.pool.Close()
		x.closeErr = x.ProxyAdapter.Close()
	})
	return x.closeErr
}
