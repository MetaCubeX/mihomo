package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/restls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	shadowtls "github.com/metacubex/mihomo/transport/sing-shadowtls"
	v2rayObfs "github.com/metacubex/mihomo/transport/v2ray-plugin"

	restlsC "github.com/3andne/restls-client-go"
	shadowsocks "github.com/metacubex/sing-shadowsocks2"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

type ShadowSocks struct {
	*Base
	method shadowsocks.Method

	option *ShadowSocksOption
	// obfs
	obfsMode        string
	obfsOption      *simpleObfsOption
	v2rayOption     *v2rayObfs.Option
	shadowTLSOption *shadowtls.ShadowTLSOption
	restlsConfig    *restlsC.Config
}

type ShadowSocksOption struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	Password          string         `proxy:"password"`
	Cipher            string         `proxy:"cipher"`
	UDP               bool           `proxy:"udp,omitempty"`
	Plugin            string         `proxy:"plugin,omitempty"`
	PluginOpts        map[string]any `proxy:"plugin-opts,omitempty"`
	UDPOverTCP        bool           `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int            `proxy:"udp-over-tcp-version,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
}

type simpleObfsOption struct {
	Mode string `obfs:"mode,omitempty"`
	Host string `obfs:"host,omitempty"`
}

type v2rayObfsOption struct {
	Mode                     string            `obfs:"mode"`
	Host                     string            `obfs:"host,omitempty"`
	Path                     string            `obfs:"path,omitempty"`
	TLS                      bool              `obfs:"tls,omitempty"`
	Fingerprint              string            `obfs:"fingerprint,omitempty"`
	Headers                  map[string]string `obfs:"headers,omitempty"`
	SkipCertVerify           bool              `obfs:"skip-cert-verify,omitempty"`
	Mux                      bool              `obfs:"mux,omitempty"`
	V2rayHttpUpgrade         bool              `obfs:"v2ray-http-upgrade,omitempty"`
	V2rayHttpUpgradeFastOpen bool              `obfs:"v2ray-http-upgrade-fast-open,omitempty"`
}

type shadowTLSOption struct {
	Password       string `obfs:"password"`
	Host           string `obfs:"host"`
	Fingerprint    string `obfs:"fingerprint,omitempty"`
	SkipCertVerify bool   `obfs:"skip-cert-verify,omitempty"`
	Version        int    `obfs:"version,omitempty"`
}

type restlsOption struct {
	Password     string `obfs:"password"`
	Host         string `obfs:"host"`
	VersionHint  string `obfs:"version-hint"`
	RestlsScript string `obfs:"restls-script,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (ss *ShadowSocks) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	useEarly := false
	switch ss.obfsMode {
	case "tls":
		c = obfs.NewTLSObfs(c, ss.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(ss.addr)
		c = obfs.NewHTTPObfs(c, ss.obfsOption.Host, port)
	case "websocket":
		var err error
		c, err = v2rayObfs.NewV2rayObfs(ctx, c, ss.v2rayOption)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
		}
	case shadowtls.Mode:
		var err error
		c, err = shadowtls.NewShadowTLS(ctx, c, ss.shadowTLSOption)
		if err != nil {
			return nil, err
		}
		useEarly = true
	case restls.Mode:
		var err error
		c, err = restls.NewRestls(ctx, c, ss.restlsConfig)
		if err != nil {
			return nil, fmt.Errorf("%s (restls) connect error: %w", ss.addr, err)
		}
		useEarly = true
	}
	useEarly = useEarly || N.NeedHandshake(c)
	if metadata.NetWork == C.UDP && ss.option.UDPOverTCP {
		uotDestination := uot.RequestDestination(uint8(ss.option.UDPOverTCPVersion))
		if useEarly {
			return ss.method.DialEarlyConn(c, uotDestination), nil
		} else {
			return ss.method.DialConn(c, uotDestination)
		}
	}
	if useEarly {
		return ss.method.DialEarlyConn(c, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort)), nil
	} else {
		return ss.method.DialConn(c, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	}
}

// DialContext implements C.ProxyAdapter
func (ss *ShadowSocks) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	return ss.DialContextWithDialer(ctx, dialer.NewDialer(ss.Base.DialOptions(opts...)...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (ss *ShadowSocks) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(ss.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(ss.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", ss.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}
	N.TCPKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ss.StreamConnContext(ctx, c, metadata)
	return NewConn(c, ss), err
}

// ListenPacketContext implements C.ProxyAdapter
func (ss *ShadowSocks) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return ss.ListenPacketWithDialer(ctx, dialer.NewDialer(ss.Base.DialOptions(opts...)...), metadata)
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (ss *ShadowSocks) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if len(ss.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(ss.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	if ss.option.UDPOverTCP {
		tcpConn, err := ss.DialContextWithDialer(ctx, dialer, metadata)
		if err != nil {
			return nil, err
		}
		return ss.ListenPacketOnStreamConn(ctx, tcpConn, metadata)
	}
	addr, err := resolveUDPAddrWithPrefer(ctx, "udp", ss.addr, ss.prefer)
	if err != nil {
		return nil, err
	}

	pc, err := dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
	if err != nil {
		return nil, err
	}
	pc = ss.method.DialPacketConn(N.NewBindPacketConn(pc, addr))
	return newPacketConn(pc, ss), nil
}

// SupportWithDialer implements C.ProxyAdapter
func (ss *ShadowSocks) SupportWithDialer() C.NetWork {
	return C.ALLNet
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (ss *ShadowSocks) ListenPacketOnStreamConn(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if ss.option.UDPOverTCP {
		// ss uot use stream-oriented udp with a special address, so we need a net.UDPAddr
		if !metadata.Resolved() {
			ip, err := resolver.ResolveIP(ctx, metadata.Host)
			if err != nil {
				return nil, errors.New("can't resolve ip")
			}
			metadata.DstIP = ip
		}

		destination := M.SocksaddrFromNet(metadata.UDPAddr())
		if ss.option.UDPOverTCPVersion == uot.LegacyVersion {
			return newPacketConn(uot.NewConn(c, uot.Request{Destination: destination}), ss), nil
		} else {
			return newPacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination}), ss), nil
		}
	}
	return nil, C.ErrNotSupport
}

// SupportUOT implements C.ProxyAdapter
func (ss *ShadowSocks) SupportUOT() bool {
	return ss.option.UDPOverTCP
}

func NewShadowSocks(option ShadowSocksOption) (*ShadowSocks, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	method, err := shadowsocks.CreateMethod(context.Background(), option.Cipher, shadowsocks.MethodOptions{
		Password: option.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("ss %s initialize error: %w", addr, err)
	}

	var v2rayOption *v2rayObfs.Option
	var obfsOption *simpleObfsOption
	var shadowTLSOpt *shadowtls.ShadowTLSOption
	var restlsConfig *restlsC.Config
	obfsMode := ""

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	if option.Plugin == "obfs" {
		opts := simpleObfsOption{Host: "bing.com"}
		if err := decoder.Decode(option.PluginOpts, &opts); err != nil {
			return nil, fmt.Errorf("ss %s initialize obfs error: %w", addr, err)
		}

		if opts.Mode != "tls" && opts.Mode != "http" {
			return nil, fmt.Errorf("ss %s obfs mode error: %s", addr, opts.Mode)
		}
		obfsMode = opts.Mode
		obfsOption = &opts
	} else if option.Plugin == "v2ray-plugin" {
		opts := v2rayObfsOption{Host: "bing.com", Mux: true}
		if err := decoder.Decode(option.PluginOpts, &opts); err != nil {
			return nil, fmt.Errorf("ss %s initialize v2ray-plugin error: %w", addr, err)
		}

		if opts.Mode != "websocket" {
			return nil, fmt.Errorf("ss %s obfs mode error: %s", addr, opts.Mode)
		}
		obfsMode = opts.Mode
		v2rayOption = &v2rayObfs.Option{
			Host:                     opts.Host,
			Path:                     opts.Path,
			Headers:                  opts.Headers,
			Mux:                      opts.Mux,
			V2rayHttpUpgrade:         opts.V2rayHttpUpgrade,
			V2rayHttpUpgradeFastOpen: opts.V2rayHttpUpgradeFastOpen,
		}

		if opts.TLS {
			v2rayOption.TLS = true
			v2rayOption.SkipCertVerify = opts.SkipCertVerify
		}
	} else if option.Plugin == shadowtls.Mode {
		obfsMode = shadowtls.Mode
		opt := &shadowTLSOption{
			Version: 2,
		}
		if err := decoder.Decode(option.PluginOpts, opt); err != nil {
			return nil, fmt.Errorf("ss %s initialize shadow-tls-plugin error: %w", addr, err)
		}

		shadowTLSOpt = &shadowtls.ShadowTLSOption{
			Password:          opt.Password,
			Host:              opt.Host,
			Fingerprint:       opt.Fingerprint,
			ClientFingerprint: option.ClientFingerprint,
			SkipCertVerify:    opt.SkipCertVerify,
			Version:           opt.Version,
		}
	} else if option.Plugin == restls.Mode {
		obfsMode = restls.Mode
		restlsOpt := &restlsOption{}
		if err := decoder.Decode(option.PluginOpts, restlsOpt); err != nil {
			return nil, fmt.Errorf("ss %s initialize restls-plugin error: %w", addr, err)
		}

		restlsConfig, err = restlsC.NewRestlsConfig(restlsOpt.Host, restlsOpt.Password, restlsOpt.VersionHint, restlsOpt.RestlsScript, option.ClientFingerprint)
		if err != nil {
			return nil, fmt.Errorf("ss %s initialize restls-plugin error: %w", addr, err)
		}

	}
	switch option.UDPOverTCPVersion {
	case uot.Version, uot.LegacyVersion:
	case 0:
		option.UDPOverTCPVersion = uot.LegacyVersion
	default:
		return nil, fmt.Errorf("ss %s unknown udp over tcp protocol version: %d", addr, option.UDPOverTCPVersion)
	}

	return &ShadowSocks{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Shadowsocks,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		method: method,

		option:          &option,
		obfsMode:        obfsMode,
		v2rayOption:     v2rayOption,
		obfsOption:      obfsOption,
		shadowTLSOption: shadowTLSOpt,
		restlsConfig:    restlsConfig,
	}, nil
}
