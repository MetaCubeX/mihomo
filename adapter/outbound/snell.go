package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/snell"
)

type Snell struct {
	*Base
	option     *SnellOption
	psk        []byte
	pool       *snell.Pool
	obfsOption *simpleObfsOption
	version    int
}

type SnellOption struct {
	BasicOption
	Name     string         `proxy:"name"`
	Server   string         `proxy:"server"`
	Port     int            `proxy:"port"`
	Psk      string         `proxy:"psk"`
	UDP      bool           `proxy:"udp,omitempty"`
	Version  int            `proxy:"version,omitempty"`
	ObfsOpts map[string]any `proxy:"obfs-opts,omitempty"`
}

type streamOption struct {
	psk        []byte
	version    int
	addr       string
	obfsOption *simpleObfsOption
}

func streamConn(c net.Conn, option streamOption) *snell.Snell {
	switch option.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, option.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(option.addr)
		c = obfs.NewHTTPObfs(c, option.obfsOption.Host, port)
	}
	return snell.StreamConn(c, option.psk, option.version)
}

// StreamConnContext implements C.ProxyAdapter
func (s *Snell) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c = streamConn(c, streamOption{s.psk, s.version, s.addr, s.obfsOption})
	if metadata.NetWork == C.UDP {
		err := snell.WriteUDPHeader(c, s.version)
		return c, err
	}
	err := snell.WriteHeader(c, metadata.String(), uint(metadata.DstPort), s.version)
	return c, err
}

// DialContext implements C.ProxyAdapter
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	if s.version == snell.Version2 && len(opts) == 0 {
		c, err := s.pool.Get()
		if err != nil {
			return nil, err
		}

		if err = snell.WriteHeader(c, metadata.String(), uint(metadata.DstPort), s.version); err != nil {
			c.Close()
			return nil, err
		}
		return NewConn(c, s), err
	}

	return s.DialContextWithDialer(ctx, dialer.NewDialer(s.Base.DialOptions(opts...)...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (s *Snell) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(s.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(s.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	return NewConn(c, s), err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return s.ListenPacketWithDialer(ctx, dialer.NewDialer(s.Base.DialOptions(opts...)...), metadata)
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (s *Snell) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (C.PacketConn, error) {
	var err error
	if len(s.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(s.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	c = streamConn(c, streamOption{s.psk, s.version, s.addr, s.obfsOption})

	err = snell.WriteUDPHeader(c, s.version)
	if err != nil {
		return nil, err
	}

	pc := snell.PacketConn(c)
	return newPacketConn(pc, s), nil
}

// SupportWithDialer implements C.ProxyAdapter
func (s *Snell) SupportWithDialer() C.NetWork {
	return C.ALLNet
}

// SupportUOT implements C.ProxyAdapter
func (s *Snell) SupportUOT() bool {
	return true
}

func NewSnell(option SnellOption) (*Snell, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	psk := []byte(option.Psk)

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	obfsOption := &simpleObfsOption{Host: "bing.com"}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}

	switch obfsOption.Mode {
	case "tls", "http", "":
		break
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}

	// backward compatible
	if option.Version == 0 {
		option.Version = snell.DefaultSnellVersion
	}
	switch option.Version {
	case snell.Version1, snell.Version2:
		if option.UDP {
			return nil, fmt.Errorf("snell version %d not support UDP", option.Version)
		}
	case snell.Version3:
	default:
		return nil, fmt.Errorf("snell version error: %d", option.Version)
	}

	s := &Snell{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Snell,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option:     &option,
		psk:        psk,
		obfsOption: obfsOption,
		version:    option.Version,
	}

	if option.Version == snell.Version2 {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			var err error
			var cDialer C.Dialer = dialer.NewDialer(s.Base.DialOptions()...)
			if len(s.option.DialerProxy) > 0 {
				cDialer, err = proxydialer.NewByName(s.option.DialerProxy, cDialer)
				if err != nil {
					return nil, err
				}
			}
			c, err := cDialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			
			return streamConn(c, streamOption{psk, option.Version, addr, obfsOption}), nil
		})
	}
	return s, nil
}
