package outbound

import (
	"context"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	mux "github.com/metacubex/sing-mux"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
)

type SingMux struct {
	ProxyAdapter
	client  *mux.Client
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

func (s *SingMux) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := s.client.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, s), err
}

func (s *SingMux) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if s.onlyTcp {
		return s.ProxyAdapter.ListenPacketContext(ctx, metadata)
	}
	if err = s.ProxyAdapter.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := s.client.ListenPacket(ctx, M.SocksaddrFromNet(metadata.UDPAddr()))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, E.New("packetConn is nil")
	}
	return newPacketConn(N.NewThreadSafePacketConn(pc), s), nil
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

func (s *SingMux) ProxyInfo() C.ProxyInfo {
	info := s.ProxyAdapter.ProxyInfo()
	info.SMUX = true
	return info
}

// Close implements C.ProxyAdapter
func (s *SingMux) Close() error {
	if s.client != nil {
		_ = s.client.Close()
	}
	return s.ProxyAdapter.Close()
}

func NewSingMux(option SingMuxOption, proxy ProxyAdapter) (ProxyAdapter, error) {
	// TODO
	// "TCP Brutal is only supported on Linux-based systems"

	singDialer := proxydialer.NewSingDialer(proxydialer.New(proxy, option.Statistic))
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
		client:       client,
		onlyTcp:      option.OnlyTcp,
	}
	return outbound, nil
}
