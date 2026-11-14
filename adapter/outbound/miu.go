package outbound

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/miu"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type Miu struct {
	*Base
	client    *miu.Client
	option    *MiuOption
	tlsConfig *vmess.TLSConfig
}

type MiuOption struct {
	BasicOption
	Name               string         `proxy:"name"`
	Server             string         `proxy:"server"`
	Port               int            `proxy:"port"`
	PSK                string         `proxy:"psk"`
	PaddingScheme      []string       `proxy:"padding-scheme,omitempty"`
	ALPN               []string       `proxy:"alpn,omitempty"`
	SNI                string         `proxy:"sni,omitempty"`
	ECHOpts            ECHOptions     `proxy:"ech-opts,omitempty"`
	RealityOpts        RealityOptions `proxy:"reality-opts,omitempty"`
	ClientFingerprint  string         `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify     bool           `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify     string         `proxy:"name-cert-verify,omitempty"`
	Fingerprint        string         `proxy:"fingerprint,omitempty"`
	Certificate        string         `proxy:"certificate,omitempty"`
	PrivateKey         string         `proxy:"private-key,omitempty"`
	UDP                bool           `proxy:"udp,omitempty"`
	IdleSessionTimeout int            `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession     int            `proxy:"min-idle-session,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (m *Miu) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := m.client.DialContext(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, m), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (m *Miu) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := m.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	// create tcp
	c, err := m.client.DialContext(ctx, uot.RequestDestination(uot.Version))
	if err != nil {
		return nil, err
	}

	// create uot on tcp
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), m), nil
}

// SupportUOT implements C.ProxyAdapter
func (m *Miu) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (m *Miu) ProxyInfo() C.ProxyInfo {
	info := m.Base.ProxyInfo()
	info.DialerProxy = m.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (m *Miu) Close() error {
	return m.client.Close()
}

// dialLane opens the outer connection of a lane: TCP through the proxy's dialer, then TLS, uTLS or
// REALITY. The TLS connection is returned as it is, without any wrapper around it: the transport
// reaches into it for raw segments.
func (m *Miu) dialLane(ctx context.Context) (net.Conn, error) {
	conn, err := m.dialer.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return nil, err
	}
	tlsConn, err := vmess.StreamTLSConn(ctx, conn, m.tlsConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func NewMiu(option MiuOption) (*Miu, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Miu{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Miu,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	realityConfig, err := option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}
	outbound.tlsConfig = &vmess.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NameCertVerify:    option.NameCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
		Reality:           realityConfig,
	}
	if outbound.tlsConfig.Host == "" {
		outbound.tlsConfig.Host = option.Server
	}

	outbound.client, err = miu.NewClient(miu.ClientConfig{
		PSK:           option.PSK,
		PaddingScheme: strings.Join(option.PaddingScheme, "\n"),
		Dial:          outbound.dialLane,
		LaneIdle:      time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdle:       option.MinIdleSession,
	})
	if err != nil {
		return nil, err
	}
	return outbound, nil
}
