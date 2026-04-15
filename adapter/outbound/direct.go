package outbound

import (
	"context"
	"fmt"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type Direct struct {
	*Base
	loopBack *loopback.Detector
}

type DirectOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := d.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	opts := d.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), opts...)
	if err != nil {
		return nil, err
	}
	return d.loopBack.NewConn(NewConn(c, d)), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Direct) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := d.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := d.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := dialer.NewDialer(d.DialOptions()...).ListenPacket(ctx, "udp", "", metadata.AddrPort())
	if err != nil {
		return nil, err
	}
	return d.loopBack.NewPacketConn(newPacketConn(pc, d)), nil
}

func (d *Direct) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || resolver.DirectHostResolver != resolver.DefaultResolver) && metadata.Host != "" {
		ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, resolver.DirectHostResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (d *Direct) IsL3Protocol(metadata *C.Metadata) bool {
	return true // tell DNSDialer don't send domain to DialContext, avoid lookback to DefaultResolver
}

func NewDirectWithOption(option DirectOption) *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Direct,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewDirect() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "DIRECT",
			Type:   C.Direct,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewCompatible() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "COMPATIBLE",
			Type:   C.Compatible,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}
