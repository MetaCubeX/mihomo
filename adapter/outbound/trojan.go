package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/trojan"
)

type Trojan struct {
	*Base
	instance *trojan.Trojan
	option   *TrojanOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *gun.TransportWrap

	realityConfig *tlsC.RealityConfig

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
	UDP               bool           `proxy:"udp,omitempty"`
	Network           string         `proxy:"network,omitempty"`
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

func (t *Trojan) plainStream(ctx context.Context, c net.Conn) (net.Conn, error) {
	if t.option.Network == "ws" {
		host, port, _ := net.SplitHostPort(t.addr)
		wsOpts := &trojan.WebsocketOption{
			Host:                     host,
			Port:                     port,
			Path:                     t.option.WSOpts.Path,
			V2rayHttpUpgrade:         t.option.WSOpts.V2rayHttpUpgrade,
			V2rayHttpUpgradeFastOpen: t.option.WSOpts.V2rayHttpUpgradeFastOpen,
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

		return t.instance.StreamWebsocketConn(ctx, c, wsOpts)
	}

	return t.instance.StreamConn(ctx, c)
}

// StreamConnContext implements C.ProxyAdapter
func (t *Trojan) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error

	if tlsC.HaveGlobalFingerprint() && len(t.option.ClientFingerprint) == 0 {
		t.option.ClientFingerprint = tlsC.GetGlobalFingerprint()
	}

	if t.transport != nil {
		c, err = gun.StreamGunWithConn(c, t.gunTLSConfig, t.gunConfig, t.realityConfig)
	} else {
		c, err = t.plainStream(ctx, c)
	}

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	if t.ssCipher != nil {
		c = t.ssCipher.StreamConn(c)
	}

	if metadata.NetWork == C.UDP {
		err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
		return c, err
	}
	err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata))
	return c, err
}

// DialContext implements C.ProxyAdapter
func (t *Trojan) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if t.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(t.transport, t.gunConfig)
		if err != nil {
			return nil, err
		}

		if t.ssCipher != nil {
			c = t.ssCipher.StreamConn(c)
		}

		if err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata)); err != nil {
			c.Close()
			return nil, err
		}

		return NewConn(c, t), nil
	}
	return t.DialContextWithDialer(ctx, dialer.NewDialer(t.Base.DialOptions(opts...)...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (t *Trojan) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(t.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(t.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", t.addr)
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
func (t *Trojan) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn

	// grpc transport
	if t.transport != nil && len(opts) == 0 {
		c, err = gun.StreamGunWithTransport(t.transport, t.gunConfig)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)

		if t.ssCipher != nil {
			c = t.ssCipher.StreamConn(c)
		}

		err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
		if err != nil {
			return nil, err
		}

		pc := t.instance.PacketConn(c)
		return newPacketConn(pc, t), err
	}
	return t.ListenPacketWithDialer(ctx, dialer.NewDialer(t.Base.DialOptions(opts...)...), metadata)
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (t *Trojan) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if len(t.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(t.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)
	c, err = t.plainStream(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	if t.ssCipher != nil {
		c = t.ssCipher.StreamConn(c)
	}

	err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}

	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

// SupportWithDialer implements C.ProxyAdapter
func (t *Trojan) SupportWithDialer() C.NetWork {
	return C.ALLNet
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (t *Trojan) ListenPacketOnStreamConn(c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

// SupportUOT implements C.ProxyAdapter
func (t *Trojan) SupportUOT() bool {
	return true
}

func NewTrojan(option TrojanOption) (*Trojan, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	tOption := &trojan.Option{
		Password:          option.Password,
		ALPN:              option.ALPN,
		ServerName:        option.Server,
		SkipCertVerify:    option.SkipCertVerify,
		Fingerprint:       option.Fingerprint,
		ClientFingerprint: option.ClientFingerprint,
	}

	if option.SNI != "" {
		tOption.ServerName = option.SNI
	}

	t := &Trojan{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Trojan,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		instance: trojan.New(tOption),
		option:   &option,
	}

	var err error
	t.realityConfig, err = option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}
	tOption.Reality = t.realityConfig

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
		dialFn := func(network, addr string) (net.Conn, error) {
			var err error
			var cDialer C.Dialer = dialer.NewDialer(t.Base.DialOptions()...)
			if len(t.option.DialerProxy) > 0 {
				cDialer, err = proxydialer.NewByName(t.option.DialerProxy, cDialer)
				if err != nil {
					return nil, err
				}
			}
			c, err := cDialer.DialContext(context.Background(), "tcp", t.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", t.addr, err.Error())
			}
			return c, nil
		}

		tlsConfig := &tls.Config{
			NextProtos:         option.ALPN,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: tOption.SkipCertVerify,
			ServerName:         tOption.ServerName,
		}

		var err error
		tlsConfig, err = ca.GetSpecifiedFingerprintTLSConfig(tlsConfig, option.Fingerprint)
		if err != nil {
			return nil, err
		}

		t.transport = gun.NewHTTP2Client(dialFn, tlsConfig, tOption.ClientFingerprint, t.realityConfig)

		t.gunTLSConfig = tlsConfig
		t.gunConfig = &gun.Config{
			ServiceName: option.GrpcOpts.GrpcServiceName,
			Host:        tOption.ServerName,
		}
	}

	return t, nil
}
