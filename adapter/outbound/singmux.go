package outbound

import (
	"context"
	"errors"
	"runtime"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	mux "github.com/sagernet/sing-mux"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type SingMux struct {
	C.ProxyAdapter
	base    ProxyBase
	client  *mux.Client
	dialer  proxydialer.SingDialer
	onlyTcp bool
}

type SingMuxOption struct {
	Enabled        bool         `proxy:"enabled,omitempty"`
	Protocol       string       `proxy:"protocol,omitempty"`
	MaxConnections int          `proxy:"max-connections,omitempty"`
	MinStreams     int          `proxy:"min-streams,omitempty"`
	MaxStreams     int          `proxy:"max-streams,omitempty"`
	Padding        bool         `proxy:"padding,omitempty"`
	Statistic      bool         `proxy:"statistic,omitempty"`
	OnlyTcp        bool         `proxy:"only-tcp,omitempty"`
	BrutalOpts     BrutalOption `proxy:"brutal-opts,omitempty"`
}

type BrutalOption struct {
	Enabled bool   `proxy:"enabled,omitempty"`
	Up      string `proxy:"up,omitempty"`
	Down    string `proxy:"down,omitempty"`
}

type ProxyBase interface {
	DialOptions(opts ...dialer.Option) []dialer.Option
}

func (s *SingMux) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	options := s.base.DialOptions(opts...)
	s.dialer.SetDialer(dialer.NewDialer(options...))
	c, err := s.client.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(CN.NewRefConn(c, s), s.ProxyAdapter), err
}

func (s *SingMux) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	if s.onlyTcp {
		return s.ProxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	}
	options := s.base.DialOptions(opts...)
	s.dialer.SetDialer(dialer.NewDialer(options...))

	// sing-mux use stream-oriented udp with a special address, so we need a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(ctx, metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}

	pc, err := s.client.ListenPacket(ctx, M.SocksaddrFromNet(metadata.UDPAddr()))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, E.New("packetConn is nil")
	}
	return newPacketConn(CN.NewRefPacketConn(CN.NewThreadSafePacketConn(pc), s), s.ProxyAdapter), nil
}

func (s *SingMux) SupportUDP() bool {
	if s.onlyTcp {
		return s.ProxyAdapter.SupportUDP()
	}
	return true
}

func (s *SingMux) SupportUOT() bool {
	if s.onlyTcp {
		return s.ProxyAdapter.SupportUOT()
	}
	return true
}

func closeSingMux(s *SingMux) {
	_ = s.client.Close()
}

func NewSingMux(option SingMuxOption, proxy C.ProxyAdapter, base ProxyBase) (C.ProxyAdapter, error) {
	// TODO
	// "TCP Brutal is only supported on Linux-based systems"

	singDialer := proxydialer.NewSingDialer(proxy, dialer.NewDialer(), option.Statistic)
	client, err := mux.NewClient(mux.Options{
		Dialer:         singDialer,
		Logger:         log.SingLogger,
		Protocol:       option.Protocol,
		MaxConnections: option.MaxConnections,
		MinStreams:     option.MinStreams,
		MaxStreams:     option.MaxStreams,
		Padding:        option.Padding,
		Brutal: mux.BrutalOptions{
			Enabled:    option.BrutalOpts.Enabled,
			SendBPS:    StringToBps(option.BrutalOpts.Up),
			ReceiveBPS: StringToBps(option.BrutalOpts.Down),
		},
	})
	if err != nil {
		return nil, err
	}
	outbound := &SingMux{
		ProxyAdapter: proxy,
		base:         base,
		client:       client,
		dialer:       singDialer,
		onlyTcp:      option.OnlyTcp,
	}
	runtime.SetFinalizer(outbound, closeSingMux)
	return outbound, nil
}
