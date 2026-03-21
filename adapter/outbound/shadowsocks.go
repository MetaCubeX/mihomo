package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/ntp"
	gost "github.com/metacubex/mihomo/transport/gost-plugin"
	"github.com/metacubex/mihomo/transport/kcptun"
	"github.com/metacubex/mihomo/transport/restls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	shadowtls "github.com/metacubex/mihomo/transport/sing-shadowtls"
	v2rayObfs "github.com/metacubex/mihomo/transport/v2ray-plugin"

	shadowsocks "github.com/metacubex/sing-shadowsocks2"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type ShadowSocks struct {
	*Base
	method shadowsocks.Method

	option *ShadowSocksOption
	// obfs
	obfsMode        string
	obfsOption      *simpleObfsOption
	v2rayOption     *v2rayObfs.Option
	gostOption      *gost.Option
	shadowTLSOption *shadowtls.ShadowTLSOption
	restlsConfig    *restls.Config
	kcptunClient    *kcptun.Client
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
	ECHOpts                  ECHOptions        `obfs:"ech-opts,omitempty"`
	Fingerprint              string            `obfs:"fingerprint,omitempty"`
	Certificate              string            `obfs:"certificate,omitempty"`
	PrivateKey               string            `obfs:"private-key,omitempty"`
	Headers                  map[string]string `obfs:"headers,omitempty"`
	SkipCertVerify           bool              `obfs:"skip-cert-verify,omitempty"`
	Mux                      bool              `obfs:"mux,omitempty"`
	V2rayHttpUpgrade         bool              `obfs:"v2ray-http-upgrade,omitempty"`
	V2rayHttpUpgradeFastOpen bool              `obfs:"v2ray-http-upgrade-fast-open,omitempty"`
}

type gostObfsOption struct {
	Mode           string            `obfs:"mode"`
	Host           string            `obfs:"host,omitempty"`
	Path           string            `obfs:"path,omitempty"`
	TLS            bool              `obfs:"tls,omitempty"`
	ECHOpts        ECHOptions        `obfs:"ech-opts,omitempty"`
	Fingerprint    string            `obfs:"fingerprint,omitempty"`
	Certificate    string            `obfs:"certificate,omitempty"`
	PrivateKey     string            `obfs:"private-key,omitempty"`
	Headers        map[string]string `obfs:"headers,omitempty"`
	SkipCertVerify bool              `obfs:"skip-cert-verify,omitempty"`
	Mux            bool              `obfs:"mux,omitempty"`
}

type shadowTLSOption struct {
	Password       string   `obfs:"password,omitempty"`
	Host           string   `obfs:"host"`
	Fingerprint    string   `obfs:"fingerprint,omitempty"`
	Certificate    string   `obfs:"certificate,omitempty"`
	PrivateKey     string   `obfs:"private-key,omitempty"`
	SkipCertVerify bool     `obfs:"skip-cert-verify,omitempty"`
	Version        int      `obfs:"version,omitempty"`
	ALPN           []string `obfs:"alpn,omitempty"`
}

type restlsOption struct {
	Password     string `obfs:"password"`
	Host         string `obfs:"host"`
	VersionHint  string `obfs:"version-hint"`
	RestlsScript string `obfs:"restls-script,omitempty"`
}

type kcpTunOption struct {
	Key          string `obfs:"key,omitempty"`
	Crypt        string `obfs:"crypt,omitempty"`
	Mode         string `obfs:"mode,omitempty"`
	Conn         int    `obfs:"conn,omitempty"`
	AutoExpire   int    `obfs:"autoexpire,omitempty"`
	ScavengeTTL  int    `obfs:"scavengettl,omitempty"`
	MTU          int    `obfs:"mtu,omitempty"`
	RateLimit    int    `obfs:"ratelimit,omitempty"`
	SndWnd       int    `obfs:"sndwnd,omitempty"`
	RcvWnd       int    `obfs:"rcvwnd,omitempty"`
	DataShard    int    `obfs:"datashard,omitempty"`
	ParityShard  int    `obfs:"parityshard,omitempty"`
	DSCP         int    `obfs:"dscp,omitempty"`
	NoComp       bool   `obfs:"nocomp,omitempty"`
	AckNodelay   bool   `obfs:"acknodelay,omitempty"`
	NoDelay      int    `obfs:"nodelay,omitempty"`
	Interval     int    `obfs:"interval,omitempty"`
	Resend       int    `obfs:"resend,omitempty"`
	NoCongestion int    `obfs:"nc,omitempty"`
	SockBuf      int    `obfs:"sockbuf,omitempty"`
	SmuxVer      int    `obfs:"smuxver,omitempty"`
	SmuxBuf      int    `obfs:"smuxbuf,omitempty"`
	FrameSize    int    `obfs:"framesize,omitempty"`
	StreamBuf    int    `obfs:"streambuf,omitempty"`
	KeepAlive    int    `obfs:"keepalive,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (ss *ShadowSocks) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	useEarly := false
	switch ss.obfsMode {
	case "tls":
		c = obfs.NewTLSObfs(c, ss.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(ss.addr)
		c = obfs.NewHTTPObfs(c, ss.obfsOption.Host, port)
	case "websocket":
		if ss.v2rayOption != nil {
			c, err = v2rayObfs.NewV2rayObfs(ctx, c, ss.v2rayOption)
		} else if ss.gostOption != nil {
			c, err = gost.NewGostWebsocket(ctx, c, ss.gostOption)
		} else {
			return nil, fmt.Errorf("plugin options is required")
		}
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
		}
	case shadowtls.Mode:
		c, err = shadowtls.NewShadowTLS(ctx, c, ss.shadowTLSOption)
		if err != nil {
			return nil, err
		}
		useEarly = true
	case restls.Mode:
		c, err = restls.NewRestls(ctx, c, ss.restlsConfig)
		if err != nil {
			return nil, fmt.Errorf("%s (restls) connect error: %w", ss.addr, err)
		}
		useEarly = true
	}
	useEarly = useEarly || N.NeedHandshake(c)
	if !useEarly {
		if ctx.Done() != nil {
			done := N.SetupContextForConn(ctx, c)
			defer done(&err)
		}
	}
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
func (ss *ShadowSocks) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var c net.Conn
	if ss.kcptunClient != nil {
		c, err = ss.kcptunClient.OpenStream(ctx, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			if err = ss.ResolveUDP(ctx, metadata); err != nil {
				return nil, nil, err
			}
			addr, err := resolveUDPAddr(ctx, "udp", ss.addr, ss.prefer)
			if err != nil {
				return nil, nil, err
			}

			pc, err := ss.dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
			if err != nil {
				return nil, nil, err
			}

			return pc, addr, nil
		})
	} else {
		c, err = ss.dialer.DialContext(ctx, "tcp", ss.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ss.StreamConnContext(ctx, c, metadata)
	return NewConn(c, ss), err
}

// ListenPacketContext implements C.ProxyAdapter
func (ss *ShadowSocks) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if ss.option.UDPOverTCP {
		tcpConn, err := ss.DialContext(ctx, metadata)
		if err != nil {
			return nil, err
		}
		return ss.ListenPacketOnStreamConn(ctx, tcpConn, metadata)
	}
	if err := ss.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	addr, err := resolveUDPAddr(ctx, "udp", ss.addr, ss.prefer)
	if err != nil {
		return nil, err
	}

	pc, err := ss.dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
	if err != nil {
		return nil, err
	}
	pc = ss.method.DialPacketConn(bufio.NewBindPacketConn(pc, addr))
	return newPacketConn(pc, ss), nil
}

// ProxyInfo implements C.ProxyAdapter
func (ss *ShadowSocks) ProxyInfo() C.ProxyInfo {
	info := ss.Base.ProxyInfo()
	info.DialerProxy = ss.option.DialerProxy
	return info
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (ss *ShadowSocks) ListenPacketOnStreamConn(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if ss.option.UDPOverTCP {
		if err = ss.ResolveUDP(ctx, metadata); err != nil {
			return nil, err
		}
		destination := M.SocksaddrFromNet(metadata.UDPAddr())
		if ss.option.UDPOverTCPVersion == uot.LegacyVersion {
			return newPacketConn(N.NewThreadSafePacketConn(uot.NewConn(c, uot.Request{Destination: destination})), ss), nil
		} else {
			return newPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), ss), nil
		}
	}
	return nil, C.ErrNotSupport
}

// SupportUOT implements C.ProxyAdapter
func (ss *ShadowSocks) SupportUOT() bool {
	return ss.option.UDPOverTCP
}

func (ss *ShadowSocks) Close() error {
	if ss.kcptunClient != nil {
		return ss.kcptunClient.Close()
	}
	return nil
}

func NewShadowSocks(option ShadowSocksOption) (*ShadowSocks, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	method, err := shadowsocks.CreateMethod(option.Cipher, shadowsocks.MethodOptions{
		Password: option.Password,
		TimeFunc: ntp.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("ss %s cipher: %s initialize error: %w", addr, option.Cipher, err)
	}

	var v2rayOption *v2rayObfs.Option
	var gostOption *gost.Option
	var obfsOption *simpleObfsOption
	var shadowTLSOpt *shadowtls.ShadowTLSOption
	var restlsConfig *restls.Config
	var kcptunClient *kcptun.Client
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
			v2rayOption.Fingerprint = opts.Fingerprint
			v2rayOption.Certificate = opts.Certificate
			v2rayOption.PrivateKey = opts.PrivateKey

			echConfig, err := opts.ECHOpts.Parse()
			if err != nil {
				return nil, fmt.Errorf("ss %s initialize v2ray-plugin error: %w", addr, err)
			}
			v2rayOption.ECHConfig = echConfig
		}
	} else if option.Plugin == "gost-plugin" {
		opts := gostObfsOption{Host: "bing.com", Mux: true}
		if err := decoder.Decode(option.PluginOpts, &opts); err != nil {
			return nil, fmt.Errorf("ss %s initialize gost-plugin error: %w", addr, err)
		}

		if opts.Mode != "websocket" {
			return nil, fmt.Errorf("ss %s obfs mode error: %s", addr, opts.Mode)
		}
		obfsMode = opts.Mode
		gostOption = &gost.Option{
			Host:    opts.Host,
			Path:    opts.Path,
			Headers: opts.Headers,
			Mux:     opts.Mux,
		}

		if opts.TLS {
			gostOption.TLS = true
			gostOption.SkipCertVerify = opts.SkipCertVerify
			gostOption.Fingerprint = opts.Fingerprint
			gostOption.Certificate = opts.Certificate
			gostOption.PrivateKey = opts.PrivateKey

			echConfig, err := opts.ECHOpts.Parse()
			if err != nil {
				return nil, fmt.Errorf("ss %s initialize gost-plugin error: %w", addr, err)
			}
			gostOption.ECHConfig = echConfig
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
			Certificate:       opt.Certificate,
			PrivateKey:        opt.PrivateKey,
			ClientFingerprint: option.ClientFingerprint,
			SkipCertVerify:    opt.SkipCertVerify,
			Version:           opt.Version,
		}

		if opt.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			shadowTLSOpt.ALPN = opt.ALPN
		} else {
			shadowTLSOpt.ALPN = shadowtls.DefaultALPN
		}
	} else if option.Plugin == restls.Mode {
		obfsMode = restls.Mode
		restlsOpt := &restlsOption{}
		if err := decoder.Decode(option.PluginOpts, restlsOpt); err != nil {
			return nil, fmt.Errorf("ss %s initialize restls-plugin error: %w", addr, err)
		}

		restlsConfig, err = restls.NewRestlsConfig(restlsOpt.Host, restlsOpt.Password, restlsOpt.VersionHint, restlsOpt.RestlsScript, option.ClientFingerprint)
		if err != nil {
			return nil, fmt.Errorf("ss %s initialize restls-plugin error: %w", addr, err)
		}

	} else if option.Plugin == kcptun.Mode {
		obfsMode = kcptun.Mode
		kcptunOpt := &kcpTunOption{}
		if err := decoder.Decode(option.PluginOpts, kcptunOpt); err != nil {
			return nil, fmt.Errorf("ss %s initialize kcptun-plugin error: %w", addr, err)
		}

		kcptunClient = kcptun.NewClient(kcptun.Config{
			Key:          kcptunOpt.Key,
			Crypt:        kcptunOpt.Crypt,
			Mode:         kcptunOpt.Mode,
			Conn:         kcptunOpt.Conn,
			AutoExpire:   kcptunOpt.AutoExpire,
			ScavengeTTL:  kcptunOpt.ScavengeTTL,
			MTU:          kcptunOpt.MTU,
			RateLimit:    kcptunOpt.RateLimit,
			SndWnd:       kcptunOpt.SndWnd,
			RcvWnd:       kcptunOpt.RcvWnd,
			DataShard:    kcptunOpt.DataShard,
			ParityShard:  kcptunOpt.ParityShard,
			DSCP:         kcptunOpt.DSCP,
			NoComp:       kcptunOpt.NoComp,
			AckNodelay:   kcptunOpt.AckNodelay,
			NoDelay:      kcptunOpt.NoDelay,
			Interval:     kcptunOpt.Interval,
			Resend:       kcptunOpt.Resend,
			NoCongestion: kcptunOpt.NoCongestion,
			SockBuf:      kcptunOpt.SockBuf,
			SmuxVer:      kcptunOpt.SmuxVer,
			SmuxBuf:      kcptunOpt.SmuxBuf,
			FrameSize:    kcptunOpt.FrameSize,
			StreamBuf:    kcptunOpt.StreamBuf,
			KeepAlive:    kcptunOpt.KeepAlive,
		})
		option.UDPOverTCP = true // must open uot
	}
	switch option.UDPOverTCPVersion {
	case uot.Version, uot.LegacyVersion:
	case 0:
		option.UDPOverTCPVersion = uot.LegacyVersion
	default:
		return nil, fmt.Errorf("ss %s unknown udp over tcp protocol version: %d", addr, option.UDPOverTCPVersion)
	}

	outbound := &ShadowSocks{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Shadowsocks,
			pdName: option.ProviderName,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		method: method,

		option:          &option,
		obfsMode:        obfsMode,
		v2rayOption:     v2rayOption,
		gostOption:      gostOption,
		obfsOption:      obfsOption,
		shadowTLSOption: shadowTLSOpt,
		restlsConfig:    restlsConfig,
		kcptunClient:    kcptunClient,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
