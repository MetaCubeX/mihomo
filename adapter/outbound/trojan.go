package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/dialer"
	tlsC "github.com/Dreamacro/clash/component/tls"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/gun"
	"github.com/Dreamacro/clash/transport/trojan"
	"github.com/Dreamacro/clash/transport/vless"
)

type Trojan struct {
	*Base
	instance *trojan.Trojan
	option   *TrojanOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *gun.TransportWrap
}

type TrojanOption struct {
	BasicOption
	Name           string      `proxy:"name"`
	Server         string      `proxy:"server"`
	Port           int         `proxy:"port"`
	Password       string      `proxy:"password"`
	ALPN           []string    `proxy:"alpn,omitempty"`
	SNI            string      `proxy:"sni,omitempty"`
	SkipCertVerify bool        `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string      `proxy:"fingerprint,omitempty"`
	UDP            bool        `proxy:"udp,omitempty"`
	Network        string      `proxy:"network,omitempty"`
	GrpcOpts       GrpcOptions `proxy:"grpc-opts,omitempty"`
	WSOpts         WSOptions   `proxy:"ws-opts,omitempty"`
	Flow           string      `proxy:"flow,omitempty"`
	FlowShow       bool        `proxy:"flow-show,omitempty"`
}

func (t *Trojan) plainStream(c net.Conn) (net.Conn, error) {
	if t.option.Network == "ws" {
		host, port, _ := net.SplitHostPort(t.addr)
		wsOpts := &trojan.WebsocketOption{
			Host: host,
			Port: port,
			Path: t.option.WSOpts.Path,
		}

		if t.option.SNI != "" {
			wsOpts.Host = t.option.SNI
		}

		if len(t.option.WSOpts.Headers) != 0 {
			header := http.Header{}
			for key, value := range t.option.WSOpts.Headers {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		return t.instance.StreamWebsocketConn(c, wsOpts)
	}

	return t.instance.StreamConn(c)
}

// StreamConn implements C.ProxyAdapter
func (t *Trojan) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	if t.transport != nil {
		c, err = gun.StreamGunWithConn(c, t.gunTLSConfig, t.gunConfig)
	} else {
		c, err = t.plainStream(c)
	}

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	c, err = t.instance.PresetXTLSConn(c)
	if err != nil {
		return nil, err
	}

	if metadata.NetWork == C.UDP {
		err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
		return c, err
	}
	err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata))
	return N.NewExtendedConn(c), err
}

// DialContext implements C.ProxyAdapter
func (t *Trojan) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if t.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(t.transport, t.gunConfig)
		if err != nil {
			return nil, err
		}

		c, err = t.instance.PresetXTLSConn(c)
		if err != nil {
			c.Close()
			return nil, err
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
	c, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.StreamConn(c, metadata)
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
	c, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)
	tcpKeepAlive(c)
	c, err = t.plainStream(c)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}

	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

// SupportWithDialer implements C.ProxyAdapter
func (t *Trojan) SupportWithDialer() bool {
	return true
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
		Password:       option.Password,
		ALPN:           option.ALPN,
		ServerName:     option.Server,
		SkipCertVerify: option.SkipCertVerify,
		FlowShow:       option.FlowShow,
		Fingerprint:    option.Fingerprint,
	}

	switch option.Network {
	case "", "tcp":
		if len(option.Flow) >= 16 {
			option.Flow = option.Flow[:16]
			switch option.Flow {
			case vless.XRO, vless.XRD, vless.XRS:
				tOption.Flow = option.Flow
			default:
				return nil, fmt.Errorf("unsupported xtls flow type: %s", option.Flow)
			}
		}
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
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		instance: trojan.New(tOption),
		option:   &option,
	}

	if option.Network == "grpc" {
		dialFn := func(network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(context.Background(), "tcp", t.addr, t.Base.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", t.addr, err.Error())
			}
			tcpKeepAlive(c)
			return c, nil
		}

		tlsConfig := &tls.Config{
			NextProtos:         option.ALPN,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: tOption.SkipCertVerify,
			ServerName:         tOption.ServerName,
		}

		if len(option.Fingerprint) == 0 {
			tlsConfig = tlsC.GetGlobalTLSConfig(tlsConfig)
		} else {
			var err error
			if tlsConfig, err = tlsC.GetSpecifiedFingerprintTLSConfig(tlsConfig, option.Fingerprint); err != nil {
				return nil, err
			}
		}

		t.transport = gun.NewHTTP2Client(dialFn, tlsConfig)

		t.gunTLSConfig = tlsConfig
		t.gunConfig = &gun.Config{
			ServiceName: option.GrpcOpts.GrpcServiceName,
			Host:        tOption.ServerName,
		}
	}

	return t, nil
}
