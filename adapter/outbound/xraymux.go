package outbound

import (
	"context"
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
)

type XrayMuxOption struct {
	Enabled        bool `proxy:"enabled,omitempty"`
	MaxConcurrency int  `proxy:"max-concurrency,omitempty"`
	MaxConnections int  `proxy:"max-connections,omitempty"`
}

type XrayMux struct {
	ProxyAdapter
	pool      *xraymux.Pool
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
	if option.MaxConcurrency == 0 {
		option.MaxConcurrency = xraymux.DefaultMaxConcurrency
	}
	if option.MaxConnections == 0 {
		option.MaxConnections = xraymux.DefaultMaxConnections
	}

	wrapper := &XrayMux{ProxyAdapter: proxy, option: option}
	wrapper.pool = xraymux.NewPool(wrapper.dialCarrier, xraymux.Options{
		MaxConcurrency: option.MaxConcurrency,
		MaxConnections: option.MaxConnections,
	})
	return wrapper, nil
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
	var globalID [8]byte
	if metadata.SourceValid() {
		globalID = utils.GlobalID(metadata.SourceAddress())
	}
	packetConn, err := x.pool.ListenPacketContext(ctx, metadata.String(), metadata.DstPort, globalID)
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
		_ = x.pool.Close()
		x.closeErr = x.ProxyAdapter.Close()
	})
	return x.closeErr
}
