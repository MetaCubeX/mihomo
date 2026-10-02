package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/nowhere"

	"github.com/metacubex/tls"
)

type NowhereOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	TCPPort        int    `proxy:"tcp-port,omitempty"`
	UDPPort        int    `proxy:"udp-port,omitempty"`
	Password       string `proxy:"password"`
	Up             string `proxy:"up,omitempty"`
	Down           string `proxy:"down,omitempty"`
	Mux            bool   `proxy:"mux,omitempty"`
	Morph          bool   `proxy:"morph,omitempty"`
	MorphPrelude   string `proxy:"morph-prelude,omitempty"`
	UDP            bool   `proxy:"udp,omitempty"`
	SNI            string `proxy:"sni,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string `proxy:"fingerprint,omitempty"`
	Certificate    string `proxy:"certificate,omitempty"`
	PrivateKey     string `proxy:"private-key,omitempty"`
}

type Nowhere struct {
	*Base
	option NowhereOption
	client *nowhere.Client
}

func NewNowhere(option NowhereOption) (*Nowhere, error) {
	if option.Server == "" || option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("nowhere: server and port (1..65535) are required")
	}
	if option.TCPPort == 0 {
		option.TCPPort = option.Port
	}
	if option.UDPPort == 0 {
		option.UDPPort = option.Port
	}
	if option.TCPPort < 1 || option.TCPPort > 65535 || option.UDPPort < 1 || option.UDPPort > 65535 {
		return nil, errors.New("nowhere: invalid carrier port")
	}
	if option.MorphPrelude != "" && option.MorphPrelude != "low7" && option.MorphPrelude != "full8" {
		return nil, errors.New("nowhere: morph-prelude must be low7 or full8")
	}
	sni := option.SNI
	if sni == "" {
		sni = option.Server
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: option.SkipCertVerify,
		},
		Fingerprint: option.Fingerprint,
		Certificate: option.Certificate,
		PrivateKey:  option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	n := &Nowhere{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Nowhere,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option,
	}
	n.dialer = option.NewDialer(n.DialOptions())
	n.client, err = nowhere.NewClient(nowhere.ClientConfig{
		Password:   option.Password,
		Up:         option.Up,
		Down:       option.Down,
		Mux:        option.Mux,
		Morph:      option.Morph,
		MorphFull8: option.MorphPrelude == "full8",
		TLSConfig:  tlsConfig,
		DialTCP: func(ctx context.Context) (net.Conn, error) {
			return n.dialer.DialContext(ctx, "tcp", net.JoinHostPort(option.Server, strconv.Itoa(option.TCPPort)))
		},
		DialUDP: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			ip, err := resolveIPWithResolver(ctx, option.Server, option.IPVersion, resolver.ProxyServerHostResolver)
			if err != nil {
				return nil, nil, err
			}
			addr := netip.AddrPortFrom(ip, uint16(option.UDPPort))
			pc, err := n.dialer.ListenPacket(ctx, "udp", "", addr)
			return pc, net.UDPAddrFromAddrPort(addr), err
		},
	})
	if err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Nowhere) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if metadata.Type == C.NOWHERE {
		var err error
		ctx, err = nowhere.ForwardContext(ctx, metadata.NowhereHops)
		if err != nil {
			return nil, err
		}
	}
	c, err := n.client.DialContext(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(c, n), nil
}

func (n *Nowhere) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if metadata.Type == C.NOWHERE {
		var err error
		ctx, err = nowhere.ForwardContext(ctx, metadata.NowhereHops)
		if err != nil {
			return nil, err
		}
	}
	if err := n.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := n.client.ListenPacketAssociation(ctx, metadata.UDPAddr().String())
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, n), nil
}

func (n *Nowhere) SupportUOT() bool {
	return n.option.Up != "udp" || n.option.Down != "udp"
}

func (n *Nowhere) Close() error {
	return n.client.Close()
}

func (n *Nowhere) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

var _ C.ProxyAdapter = (*Nowhere)(nil)
