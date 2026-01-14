package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/trojan"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type Trojan struct {
	*Base
	option      *TrojanOption
	hexPassword [trojan.KeyLength]byte

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *gun.TransportWrap

	realityConfig *tlsC.RealityConfig
	echConfig     *ech.Config

	ssCipher core.Cipher
}

type TrojanOption struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	Password          string         `proxy:"password"`
	ALPN              []string       `proxy:"alpn,omitempty"`
	SNI               string         `proxy:"sni,omitempty"`
	SkipCertVerify    bool           `proxy:"skip-cert-verify,omitempty"`
	Fingerprint       string         `proxy:"fingerprint,omitempty"`
	Certificate       string         `proxy:"certificate,omitempty"`
	PrivateKey        string         `proxy:"private-key,omitempty"`
	UDP               bool           `proxy:"udp,omitempty"`
	Network           string         `proxy:"network,omitempty"`
	ECHOpts           ECHOptions     `proxy:"ech-opts,omitempty"`
	RealityOpts       RealityOptions `proxy:"reality-opts,omitempty"`
	GrpcOpts          GrpcOptions    `proxy:"grpc-opts,omitempty"`
	WSOpts            WSOptions      `proxy:"ws-opts,omitempty"`
	SSOpts            TrojanSSOption `proxy:"ss-opts,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
}

// TrojanSSOption from https://github.com/p4gefau1t/trojan-go/blob/v0.10.6/tunnel/shadowsocks/config.go#L5
type TrojanSSOption struct {
	Enabled  bool   `proxy:"enabled,omitempty"`
	Method   string `proxy:"method,omitempty"`
	Password string `proxy:"password,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (t *Trojan) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	switch t.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(t.addr)

		wsOpts := &vmess.WebsocketConfig{
			Host:                     host,
			Port:                     port,
			Path:                     t.option.WSOpts.Path,
			MaxEarlyData:             t.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName:      t.option.WSOpts.EarlyDataHeaderName,
			V2rayHttpUpgrade:         t.option.WSOpts.V2rayHttpUpgrade,
			V2rayHttpUpgradeFastOpen: t.option.WSOpts.V2rayHttpUpgradeFastOpen,
			ClientFingerprint:        t.option.ClientFingerprint,
			ECHConfig:                t.echConfig,
			Headers:                  http.Header{},
		}

		if t.option.SNI != "" {
			wsOpts.Host = t.option.SNI
		}

		if len(t.option.WSOpts.Headers) != 0 {
			for key, value := range t.option.WSOpts.Headers {
				wsOpts.Headers.Add(key, value)
			}
		}

		alpn := trojan.DefaultWebsocketALPN
		if t.option.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			alpn = t.option.ALPN
		}

		wsOpts.TLS = true
		wsOpts.TLSConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				NextProtos:         alpn,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: t.option.SkipCertVerify,
				ServerName:         t.option.SNI,
			},
			Fingerprint: t.option.Fingerprint,
			Certificate: t.option.Certificate,
			PrivateKey:  t.option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}

		c, err = vmess.StreamWebsocketConn(ctx, c, wsOpts)
	case "grpc":
		c, err = gun.StreamGunWithConn(c, t.gunTLSConfig, t.gunConfig, t.echConfig, t.realityConfig)
	default:
		// default tcp network
		// handle TLS
		alpn := trojan.DefaultALPN
		if t.option.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			alpn = t.option.ALPN
		}
		c, err = vmess.StreamTLSConn(ctx, c, &vmess.TLSConfig{
			Host:              t.option.SNI,
			SkipCertVerify:    t.option.SkipCertVerify,
			FingerPrint:       t.option.Fingerprint,
			Certificate:       t.option.Certificate,
			PrivateKey:        t.option.PrivateKey,
			ClientFingerprint: t.option.ClientFingerprint,
			NextProtos:        alpn,
			ECH:               t.echConfig,
			Reality:           t.realityConfig,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	return t.streamConnContext(ctx, c, metadata)
}

func (t *Trojan) streamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	if t.ssCipher != nil {
		c = t.ssCipher.StreamConn(c)
	}

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	command := trojan.CommandTCP
	if metadata.NetWork == C.UDP {
		command = trojan.CommandUDP
	}
	err = trojan.WriteHeader(c, t.hexPassword, command, serializesSocksAddr(metadata))
	return c, err
}

func (t *Trojan) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	command := trojan.CommandTCP
	if metadata.NetWork == C.UDP {
		command = trojan.CommandUDP
	}
	err = trojan.WriteHeader(c, t.hexPassword, command, serializesSocksAddr(metadata))
	return err
}

// DialContext implements C.ProxyAdapter
func (t *Trojan) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var c net.Conn
	// gun transport
	if t.transport != nil {
		c, err = gun.StreamGunWithTransport(t.transport, t.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)

		c, err = t.streamConnContext(ctx, c, metadata)
		if err != nil {
			return nil, err
		}

		return NewConn(c, t), nil
	}
	c, err = t.dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *Trojan) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	var c net.Conn

	// grpc transport
	if t.transport != nil {
		c, err = gun.StreamGunWithTransport(t.transport, t.gunConfig)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)

		c, err = t.streamConnContext(ctx, c, metadata)
		if err != nil {
			return nil, err
		}

		pc := trojan.NewPacketConn(c)
		return newPacketConn(pc, t), err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err = t.dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)
	c, err = t.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	pc := trojan.NewPacketConn(c)
	return newPacketConn(pc, t), err
}

// SupportUOT implements C.ProxyAdapter
func (t *Trojan) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *Trojan) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *Trojan) Close() error {
	if t.transport != nil {
		return t.transport.Close()
	}
	return nil
}

func NewTrojan(option TrojanOption) (*Trojan, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	if option.SNI == "" {
		option.SNI = option.Server
	}

	t := &Trojan{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Trojan,
			pdName: option.ProviderName,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option:      &option,
		hexPassword: trojan.Key(option.Password),
	}
	t.dialer = option.NewDialer(t.DialOptions())

	var err error
	t.realityConfig, err = option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}

	t.echConfig, err = option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	if option.SSOpts.Enabled {
		if option.SSOpts.Password == "" {
			return nil, errors.New("empty password")
		}
		if option.SSOpts.Method == "" {
			option.SSOpts.Method = "AES-128-GCM"
		}
		ciph, err := core.PickCipher(option.SSOpts.Method, nil, option.SSOpts.Password)
		if err != nil {
			return nil, err
		}
		t.ssCipher = ciph
	}

	if option.Network == "grpc" {
		dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := t.dialer.DialContext(ctx, "tcp", t.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", t.addr, err.Error())
			}
			return c, nil
		}

		tlsConfig, err := ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				NextProtos:         option.ALPN,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: option.SkipCertVerify,
				ServerName:         option.SNI,
			},
			Fingerprint: option.Fingerprint,
			Certificate: option.Certificate,
			PrivateKey:  option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}

		t.transport = gun.NewHTTP2Client(dialFn, tlsConfig, option.ClientFingerprint, t.echConfig, t.realityConfig)

		t.gunTLSConfig = tlsConfig
		t.gunConfig = &gun.Config{
			ServiceName:       option.GrpcOpts.GrpcServiceName,
			UserAgent:         option.GrpcOpts.GrpcUserAgent,
			Host:              option.SNI,
			ClientFingerprint: option.ClientFingerprint,
		}
	}

	return t, nil
}
