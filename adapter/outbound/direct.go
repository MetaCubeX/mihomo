package outbound

import (
	"context"
	"net"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
)

type Direct struct {
	*Base
}

// DialContext implements C.ProxyAdapter
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	opts = append(opts, dialer.WithResolver(resolver.DefaultResolver))
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), d.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	tcpKeepAlive(c)
	return NewConn(c, d), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Direct) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	opts = append(opts, dialer.WithResolver(resolver.DefaultResolver))
	pc, err := dialer.ListenPacket(ctx, dialer.ParseNetwork("udp", metadata.DstIP), "", d.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	return newPacketConn(&directPacketConn{pc}, d), nil
}

type directPacketConn struct {
	net.PacketConn
}

func NewDirect() *Direct {
	return &Direct{
		Base: &Base{
			name:   "DIRECT",
			tp:     C.Direct,
			udp:    true,
			prefer: C.DualStack,
		},
	}
}

func NewCompatible() *Direct {
	return &Direct{
		Base: &Base{
			name:   "COMPATIBLE",
			tp:     C.Compatible,
			udp:    true,
			prefer: C.DualStack,
		},
	}
}
