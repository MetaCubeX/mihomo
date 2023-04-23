package outbound

import (
	"context"
	"net"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/proxydialer"
	C "github.com/Dreamacro/clash/constant"

	mux "github.com/sagernet/sing-mux"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type SingMux struct {
	C.ProxyAdapter
	base   ProxyBase
	client *mux.Client
	dialer *muxSingDialer
}

type SingMuxOption struct {
	Enabled        bool   `proxy:"enabled,omitempty"`
	Protocol       string `proxy:"protocol,omitempty"`
	MaxConnections int    `proxy:"max-connections,omitempty"`
	MinStreams     int    `proxy:"min-streams,omitempty"`
	MaxStreams     int    `proxy:"max-streams,omitempty"`
	Padding        bool   `proxy:"padding,omitempty"`
}

type ProxyBase interface {
	DialOptions(opts ...dialer.Option) []dialer.Option
}

type muxSingDialer struct {
	dialer dialer.Dialer
	proxy  C.ProxyAdapter
}

var _ N.Dialer = (*muxSingDialer)(nil)

func (d *muxSingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var cDialer C.Dialer = proxydialer.New(d.proxy, d.dialer, false)
	return cDialer.DialContext(ctx, network, destination.String())
}

func (d *muxSingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var cDialer C.Dialer = proxydialer.New(d.proxy, d.dialer, false)
	return cDialer.ListenPacket(ctx, "udp", "", destination.AddrPort())
}

func (s *SingMux) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	options := s.base.DialOptions(opts...)
	s.dialer.dialer = dialer.NewDialer(options...)
	c, err := s.client.DialContext(ctx, "tcp", M.ParseSocksaddr(metadata.RemoteAddress()))
	if err != nil {
		return nil, err
	}
	return NewConn(c, s.ProxyAdapter), err
}

func (s *SingMux) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	options := s.base.DialOptions(opts...)
	s.dialer.dialer = dialer.NewDialer(options...)
	pc, err := s.client.ListenPacket(ctx, M.ParseSocksaddr(metadata.RemoteAddress()))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, E.New("packetConn is nil")
	}
	return newPacketConn(pc, s.ProxyAdapter), nil
}

func NewSingMux(option SingMuxOption, proxy C.ProxyAdapter, base ProxyBase) (C.ProxyAdapter, error) {
	singDialer := &muxSingDialer{dialer: dialer.NewDialer(), proxy: proxy}
	client, err := mux.NewClient(mux.Options{
		Context:        context.TODO(),
		Dialer:         singDialer,
		Protocol:       option.Protocol,
		MaxConnections: option.MaxConnections,
		MinStreams:     option.MinStreams,
		MaxStreams:     option.MaxStreams,
		Padding:        option.Padding,
	})
	if err != nil {
		return nil, err
	}
	return &SingMux{
		ProxyAdapter: proxy,
		base:         base,
		client:       client,
		dialer:       singDialer,
	}, nil
}
