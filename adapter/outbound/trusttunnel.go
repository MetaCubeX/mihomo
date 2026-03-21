package outbound

import (
	"context"
	"net"
	"net/netip"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/trusttunnel"
	"github.com/metacubex/mihomo/transport/vmess"
)

type TrustTunnel struct {
	*Base
	client *trusttunnel.Client
	option *TrustTunnelOption
}

type TrustTunnelOption struct {
	BasicOption
	Name              string     `proxy:"name"`
	Server            string     `proxy:"server"`
	Port              int        `proxy:"port"`
	UserName          string     `proxy:"username,omitempty"`
	Password          string     `proxy:"password,omitempty"`
	ALPN              []string   `proxy:"alpn,omitempty"`
	SNI               string     `proxy:"sni,omitempty"`
	ECHOpts           ECHOptions `proxy:"ech-opts,omitempty"`
	ClientFingerprint string     `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify    bool       `proxy:"skip-cert-verify,omitempty"`
	Fingerprint       string     `proxy:"fingerprint,omitempty"`
	Certificate       string     `proxy:"certificate,omitempty"`
	PrivateKey        string     `proxy:"private-key,omitempty"`
	UDP               bool       `proxy:"udp,omitempty"`
	HealthCheck       bool       `proxy:"health-check,omitempty"`

	Quic                 bool   `proxy:"quic,omitempty"`
	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`
}

func (t *TrustTunnel) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.client.Dial(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *TrustTunnel) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	pc, err := t.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}

	return newPacketConn(N.NewThreadSafePacketConn(pc), t), nil
}

// SupportUOT implements C.ProxyAdapter
func (t *TrustTunnel) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *TrustTunnel) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *TrustTunnel) Close() error {
	return t.client.Close()
}

func NewTrustTunnel(option TrustTunnelOption) (*TrustTunnel, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &TrustTunnel{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.TrustTunnel,
			pdName: option.ProviderName,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	tOption := trusttunnel.ClientOptions{
		Dialer: outbound.dialer,
		ResolvUDP: func(ctx context.Context, server string) (netip.AddrPort, error) {
			udpAddr, err := resolveUDPAddr(ctx, "udp", server, option.IPVersion)
			if err != nil {
				return netip.AddrPort{}, err
			}
			return udpAddr.AddrPort(), nil
		},
		Server:                addr,
		Username:              option.UserName,
		Password:              option.Password,
		QUIC:                  option.Quic,
		QUICCongestionControl: option.CongestionController,
		QUICCwnd:              option.CWND,
		HealthCheck:           option.HealthCheck,
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	tlsConfig := &vmess.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
	}
	if tlsConfig.Host == "" {
		tlsConfig.Host = option.Server
	}
	tOption.TLSConfig = tlsConfig

	client, err := trusttunnel.NewClient(context.TODO(), tOption)
	if err != nil {
		return nil, err
	}
	outbound.client = client

	return outbound, nil
}
