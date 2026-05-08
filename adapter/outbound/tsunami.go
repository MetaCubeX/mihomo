package outbound

import (
	"context"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tsunami"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type Tsunami struct {
	*Base
	client *tsunami.Client
	option *TsunamiOption
}

type TsunamiOption struct {
	BasicOption
	Name              string     `proxy:"name"`
	Server            string     `proxy:"server"`
	Port              int        `proxy:"port"`
	Password          string     `proxy:"password"`
	ALPN              []string   `proxy:"alpn,omitempty"`
	SNI               string     `proxy:"sni,omitempty"`
	ECHOpts           ECHOptions `proxy:"ech-opts,omitempty"`
	ClientFingerprint string     `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify    bool       `proxy:"skip-cert-verify,omitempty"`
	Fingerprint       string     `proxy:"fingerprint,omitempty"`
	Certificate       string     `proxy:"certificate,omitempty"`
	PrivateKey        string     `proxy:"private-key,omitempty"`
	UDP               bool       `proxy:"udp,omitempty"`
}

func (t *Tsunami) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.client.CreateProxy(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *Tsunami) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	// create tcp connection for UoT
	c, err := t.client.CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		return nil, err
	}

	// create uot on tcp
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return newPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), t), nil
}

// SupportUOT implements C.ProxyAdapter
func (t *Tsunami) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *Tsunami) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *Tsunami) Close() error {
	return t.client.Close()
}

func NewTsunami(option TsunamiOption) (*Tsunami, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Tsunami{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tsunami,
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
	singDialer := proxydialer.NewSingDialer(outbound.dialer)

	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	// TSUNAMI requires TLS 1.3 with ALPN h2
	alpn := option.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h2"}
	}

	tlsConfig := &vmess.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NextProtos:        alpn,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
	}
	if tlsConfig.Host == "" {
		tlsConfig.Host = option.Server
	}

	tOption := tsunami.ClientConfig{
		Password:  option.Password,
		Server:    M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		Dialer:    singDialer,
		TLSConfig: tlsConfig,
	}

	client := tsunami.NewClient(context.TODO(), tOption)
	outbound.client = client

	return outbound, nil
}
