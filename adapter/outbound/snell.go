package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/singsnell/snellv6"
	"github.com/metacubex/mihomo/transport/snell"

	M "github.com/metacubex/sing/common/metadata"
	singN "github.com/metacubex/sing/common/network"
)

type Snell struct {
	*Base
	option          *SnellOption
	psk             []byte
	pool            *snell.Pool
	v6              *snellv6.Client
	obfsOption      *simpleObfsOption
	shadowTLSOption *shadowtls.ShadowTLSOption
	restlsConfig    *restls.Config
	jlsConfig       *jls.ClientConfig
	version         int
	reuse           bool
}

type SnellOption struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	Psk               string         `proxy:"psk"`
	UDP               bool           `proxy:"udp,omitempty"`
	Version           int            `proxy:"version,omitempty"`
	Reuse             bool           `proxy:"reuse,omitempty"`
	Mode              string         `proxy:"mode,omitempty"` // v6 only: default / unshaped / unsafe-raw
	ObfsOpts          map[string]any `proxy:"obfs-opts,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
}

var (
	errSnellV6UDPStream    = errors.New("snell v6 udp must be created with ListenPacketContext")
	errSnellV6ListenPacket = errors.New("snell v6 dialer does not support ListenPacket")
)

// obfsConnContext wraps the raw server connection with the configured
// obfuscation layer, which is shared by every Snell version.
func (s *Snell) obfsConnContext(ctx context.Context, c net.Conn) (net.Conn, error) {
	var err error
	switch s.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, s.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(s.addr)
		c = obfs.NewHTTPObfs(c, s.obfsOption.Host, port)
	case shadowtls.Mode:
		c, err = shadowtls.NewShadowTLS(ctx, c, s.shadowTLSOption)
		if err != nil {
			return nil, err
		}
	case restls.Mode:
		c, err = restls.NewRestls(ctx, c, s.restlsConfig)
		if err != nil {
			return nil, err
		}
	case jls.Mode:
		c, err = jls.NewClient(ctx, c, s.jlsConfig)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (s *Snell) streamConnContext(ctx context.Context, c net.Conn) (*snell.Snell, error) {
	c, err := s.obfsConnContext(ctx, c)
	if err != nil {
		return nil, err
	}
	return snell.StreamConn(c, s.psk, s.version), nil
}

// StreamConnContext implements C.ProxyAdapter
func (s *Snell) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if s.version == snell.Version6 {
		return s.streamV6ConnContext(ctx, c, metadata)
	}
	c, err := s.streamConnContext(ctx, c)
	if err != nil {
		return nil, err
	}
	err = s.writeHeaderContext(ctx, c, metadata)
	return c, err
}

func (s *Snell) streamV6ConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	if metadata.NetWork == C.UDP {
		return nil, errSnellV6UDPStream
	}
	c, err = s.obfsConnContext(ctx, c)
	if err != nil {
		return nil, err
	}
	destination := M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort)
	if N.NeedHandshake(c) {
		return s.v6.DialEarlyConn(c, destination), nil
	}
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	return s.v6.DialConn(c, destination)
}

func (s *Snell) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	if metadata.NetWork == C.UDP {
		err = snell.WriteUDPHeader(c, s.version)
		if err == nil && s.version >= snell.Version4 {
			if sc, ok := c.(*snell.Snell); ok {
				err = sc.ReadReply()
			}
		}
		return
	}
	err = snell.WriteHeaderWithReuse(c, metadata.String(), uint(metadata.DstPort), s.version, s.reuse)
	return
}

// DialContext implements C.ProxyAdapter
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.reuse {
		if s.version == snell.Version6 {
			// the v6 client owns its own session pool and dials through v6Dialer
			c, err := s.v6.DialContext(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
			}
			return NewConn(c, s), nil
		}

		c, err := s.pool.Get()
		if err != nil {
			return nil, err
		}

		if err = s.writeHeaderContext(ctx, c, metadata); err != nil {
			_ = c.Close()
			return nil, err
		}
		if pc, ok := c.(*snell.PoolConn); ok {
			pc.MarkReusable()
		}
		return NewConn(c, s), err
	}

	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
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
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	if s.version == snell.Version6 {
		c, err = s.obfsConnContext(ctx, c)
		if err != nil {
			return nil, err
		}
		var pc singN.NetPacketConn
		pc, err = s.v6.DialPacketConn(c)
		if err != nil {
			return nil, err
		}
		return NewPacketConn(N.NewThreadSafePacketConn(pc), s), nil
	}

	c, err = s.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	pc := snell.PacketConn(c)
	return NewPacketConn(pc, s), nil
}

// SupportUOT implements C.ProxyAdapter
func (s *Snell) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (s *Snell) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (s *Snell) Close() error {
	if s.v6 != nil {
		_ = s.v6.Close()
	}
	return s.Base.Close()
}

// v6Dialer lets the snellv6 session pool dial the server through the
// adapter's own dialer and obfuscation settings.
type v6Dialer struct {
	s *Snell
}

func (d v6Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	c, err := d.s.dialer.DialContext(ctx, "tcp", d.s.addr)
	if err != nil {
		return nil, err
	}
	c, err = d.s.obfsConnContext(ctx, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (d v6Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errSnellV6ListenPacket
}

var _ singN.Dialer = v6Dialer{}

func NewSnell(option SnellOption) (*Snell, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	psk := []byte(option.Psk)

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	obfsOption := &simpleObfsOption{Host: "bing.com"}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}

	var shadowTLSOpt *shadowtls.ShadowTLSOption
	var restlsConfig *restls.Config
	var jlsConfig *jls.ClientConfig
	switch obfsOption.Mode {
	case "tls", "http", "":
		break
	case shadowtls.Mode:
		opt := &shadowTLSOption{
			Version: 2,
		}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize shadow-tls-plugin error: %w", addr, err)
		}

		shadowTLSOpt = &shadowtls.ShadowTLSOption{
			Password:          opt.Password,
			Host:              opt.Host,
			Fingerprint:       opt.Fingerprint,
			Certificate:       opt.Certificate,
			PrivateKey:        opt.PrivateKey,
			ClientFingerprint: option.ClientFingerprint,
			SkipCertVerify:    opt.SkipCertVerify,
			NameCertVerify:    opt.NameCertVerify,
			Version:           opt.Version,
		}

		if opt.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			shadowTLSOpt.ALPN = opt.ALPN
		} else {
			shadowTLSOpt.ALPN = shadowtls.DefaultALPN
		}
	case restls.Mode:
		opt := &restlsOption{}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
		}

		var err error
		restlsConfig, err = restls.NewRestlsConfig(opt.Host, opt.Password, opt.VersionHint, opt.RestlsScript, option.ClientFingerprint)
		if err != nil {
			return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
		}
		restlsConfig.InsecureSkipVerify = opt.SkipCertVerify
		if opt.Fingerprint != "" {
			if err = restls.SetFingerprint(restlsConfig, opt.Fingerprint, opt.NameCertVerify); err != nil {
				return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
			}
		} else if opt.NameCertVerify != "" {
			restls.SetNameCertVerify(restlsConfig, opt.NameCertVerify)
		}
		restlsConfig.ForceTLS12 = opt.ForceTLS12
	case jls.Mode:
		opt := &jlsOption{}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize jls-plugin error: %w", addr, err)
		}

		var err error
		jlsConfig, err = jls.NewClientConfig(opt.Host, opt.Username, opt.Password, opt.ALPN)
		if err != nil {
			return nil, fmt.Errorf("snell %s initialize jls-plugin error: %w", addr, err)
		}
		jlsConfig.ClientFingerprint = option.ClientFingerprint
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}

	// backward compatible
	if option.Version == 0 {
		option.Version = snell.DefaultSnellVersion
	}
	if option.Version == snell.Version5 {
		// Snell v5 servers are backward-compatible with v4 clients.
		option.Version = snell.Version4
	}
	reuse := option.Version == snell.Version2 ||
		((option.Version == snell.Version4 || option.Version == snell.Version6) && option.Reuse)
	var v6Mode snellv6.Mode
	switch option.Version {
	case snell.Version1, snell.Version2:
		if option.UDP {
			return nil, fmt.Errorf("snell version %d not support UDP", option.Version)
		}
	case snell.Version3, snell.Version4:
	case snell.Version6:
		// snell-server v6 rejects PSKs outside the 12..255-byte range
		if len(psk) < 12 || len(psk) > 255 {
			return nil, fmt.Errorf("snell %s version 6 psk length must be between 12 and 255 bytes", addr)
		}
		switch obfsOption.Mode {
		case "tls", "http":
			// v6 replaced the simple-obfs layer with PSK-derived traffic shaping
			return nil, fmt.Errorf("snell %s version 6 does not support obfs mode %s", addr, obfsOption.Mode)
		}
		var err error
		v6Mode, err = snellv6.ParseMode(option.Mode)
		if err != nil {
			return nil, fmt.Errorf("snell %s %w", addr, err)
		}
	default:
		return nil, fmt.Errorf("snell version error: %d", option.Version)
	}
	if option.Mode != "" && option.Version != snell.Version6 {
		return nil, fmt.Errorf("snell %s mode is only supported on version 6", addr)
	}

	s := &Snell{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Snell,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:          &option,
		psk:             psk,
		obfsOption:      obfsOption,
		shadowTLSOption: shadowTLSOpt,
		restlsConfig:    restlsConfig,
		jlsConfig:       jlsConfig,
		version:         option.Version,
		reuse:           reuse,
	}
	s.dialer = option.NewDialer(s.DialOptions())

	if s.version == snell.Version6 {
		client, err := snellv6.NewClient(snellv6.ClientOptions{
			PSK:    psk,
			Mode:   v6Mode,
			Reuse:  reuse,
			Dialer: v6Dialer{s: s},
			Server: M.ParseSocksaddr(addr),
		})
		if err != nil {
			return nil, fmt.Errorf("snell %s %w", addr, err)
		}
		s.v6 = client
		return s, nil
	}

	if s.reuse {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			c, err := s.dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}

			sc, err := s.streamConnContext(ctx, c)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			return sc, nil
		})
	}
	return s, nil
}
