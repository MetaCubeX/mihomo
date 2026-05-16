package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gost"
)

type GostRelay struct {
	*Base
	dialer C.Dialer
	option *GostRelayOption
}

type GostRelayOption struct {
	BasicOption
	Name              string `proxy:"name"`
	Server            string `proxy:"server"`
	Port              int    `proxy:"port"`
	Forward           bool   `proxy:"forward,omitempty"`
	UDP               bool   `proxy:"udp,omitempty"`
	TLS               bool   `proxy:"tls,omitempty"`
	Mux               bool   `proxy:"mux,omitempty"`
	SNI               string `proxy:"sni,omitempty"`
	Username          string `proxy:"username,omitempty"`
	Password          string `proxy:"password,omitempty"`
	SkipCertVerify    bool   `proxy:"skip-cert-verify,omitempty"`
	Fingerprint       string `proxy:"fingerprint,omitempty"`
	Certificate       string `proxy:"certificate,omitempty"`
	PrivateKey        string `proxy:"private-key,omitempty"`
	ClientFingerprint string `proxy:"client-fingerprint,omitempty"`
}

func (g *GostRelay) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := g.dialer.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", g.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	return NewConn(c, g), nil
}

func (g *GostRelay) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = g.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	pc, err := g.dialer.ListenPacket(ctx, "udp", "", metadata.AddrPort())
	if err != nil {
		return nil, fmt.Errorf("%s udp connect error: %w", g.addr, err)
	}

	return newPacketConn(pc, g), nil
}

func (g *GostRelay) ProxyInfo() C.ProxyInfo {
	info := g.Base.ProxyInfo()
	info.DialerProxy = g.option.DialerProxy
	info.SMUX = g.option.Mux
	return info
}

func NewGostRelay(option GostRelayOption) (*GostRelay, error) {
	if option.Server == "" || option.Port <= 0 || option.Port > 0xffff {
		return nil, fmt.Errorf("gost-relay %s requires a valid server and port", option.Name)
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	relay := &GostRelay{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.GostRelay,
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

	relay.dialer = gost.NewRelayDialer(option.NewDialer(relay.DialOptions()), &gost.RelayOption{
		Server:            option.Server,
		Port:              option.Port,
		Forward:           option.Forward,
		TLS:               option.TLS,
		Mux:               option.Mux,
		SNI:               option.SNI,
		Username:          option.Username,
		Password:          option.Password,
		SkipCertVerify:    option.SkipCertVerify,
		Fingerprint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
	})
	return relay, nil
}
