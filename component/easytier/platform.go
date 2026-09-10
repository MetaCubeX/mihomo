package easytier

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/easytier/easytier/easytier-go/platform"
	D "github.com/miekg/dns"
)

// Services wraps a mihomo dialer as EasyTier platform capabilities.
func Services(d C.Dialer) platform.Services {
	return platform.Services{
		Sockets:     SocketFactory{Dialer: d},
		DNS:         DNSResolver{},
		Environment: ConnectorEnvironment{Dialer: d},
	}
}

// SocketFactory creates sockets through mihomo's dialer.
//
// EasyTier BindDevice/SocketMark/reuse options are ignored so hole punching
// can bind local UDP ports. Interface, routing-mark, and dialer-proxy stay on
// the mihomo dialer. Internal TCP reservations bind locally even when
// dialer-proxy is set. FakeTCP is not supported.
type SocketFactory struct {
	Dialer C.Dialer
}

func (s SocketFactory) ConnectTCP(ctx context.Context, options platform.TCPConnectOptions) (net.Conn, error) {
	if options.Purpose == platform.TCPConnectFake {
		return nil, fmt.Errorf("easytier: FakeTCP is not supported")
	}
	if options.RemoteAddr == nil {
		return nil, fmt.Errorf("easytier: TCP connect is missing a remote address")
	}
	network := tcpNetwork(options.Bind)
	return s.Dialer.DialContext(ctx, network, options.RemoteAddr.String())
}

func (s SocketFactory) BindUDP(ctx context.Context, options platform.UDPBindOptions) (net.PacketConn, error) {
	network, address := udpBind(options)
	return s.Dialer.ListenPacket(ctx, network, address, netip.AddrPort{})
}

func (s SocketFactory) ListenTCP(ctx context.Context, options platform.TCPListenOptions) (net.Listener, error) {
	if options.Bind.Context.NetNS != nil {
		return nil, fmt.Errorf("easytier: network namespaces are not supported")
	}
	address := ":0"
	if options.Bind.LocalAddr != nil {
		address = options.Bind.LocalAddr.String()
	}
	network := tcpNetwork(options.Bind)
	reuse := options.Bind.ReusePort || options.Bind.ReuseAddr != nil && *options.Bind.ReuseAddr
	listenOpts := []dialer.Option{dialer.WithAddrReuse(reuse)}
	if direct, ok := s.Dialer.(dialer.Dialer); ok {
		return dialer.Listen(ctx, network, address, append(listenOpts, dialer.WithOption(direct.Opt))...)
	}
	if externalTCPListen(options.Purpose) {
		return nil, fmt.Errorf("easytier: TCP listeners are unavailable through a proxy or custom dialer")
	}
	// ProxyNAT, port leases, and hole-punch reservations must bind on the host
	// even when peer traffic uses dialer-proxy.
	return dialer.Listen(ctx, network, address, listenOpts...)
}

func externalTCPListen(purpose platform.TCPListenPurpose) bool {
	switch purpose {
	case platform.TCPListenDirect, platform.TCPListenManual:
		return true
	default:
		return false
	}
}

func tcpNetwork(options platform.TCPBindOptions) string {
	if options.LocalAddr != nil && options.LocalAddr.IP.To4() != nil {
		return "tcp4"
	}
	if options.OnlyV6 || options.Context.IPVersion == platform.IPVersionV6 {
		return "tcp6"
	}
	if options.Context.IPVersion == platform.IPVersionV4 {
		return "tcp4"
	}
	return "tcp"
}

func udpBind(options platform.UDPBindOptions) (network, address string) {
	if options.LocalAddr != nil {
		address = options.LocalAddr.String()
		if options.LocalAddr.IP.To4() != nil {
			return "udp4", address
		}
		if len(options.LocalAddr.IP) != 0 {
			if options.OnlyV6 || options.LocalAddr.IP.To16() != nil && options.LocalAddr.IP.To4() == nil {
				return "udp6", address
			}
			return "udp", address
		}
		if options.OnlyV6 || options.Context.IPVersion == platform.IPVersionV6 {
			return "udp6", address
		}
		if options.Context.IPVersion == platform.IPVersionV4 {
			return "udp4", address
		}
		return "udp", address
	}
	switch {
	case options.OnlyV6 || options.Context.IPVersion == platform.IPVersionV6:
		return "udp6", "[::]:0"
	case options.Context.IPVersion == platform.IPVersionV4:
		return "udp4", "0.0.0.0:0"
	default:
		return "udp", ":0"
	}
}

// DNSResolver resolves EasyTier control-plane names through the proxy-server resolver.
type DNSResolver struct{}

func (DNSResolver) LookupIP(ctx context.Context, query platform.DNSQuery) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(query.Host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	switch query.IPVersion {
	case 4:
		return resolver.LookupIPv4WithResolver(ctx, query.Host, resolver.ProxyServerHostResolver)
	case 6:
		return resolver.LookupIPv6WithResolver(ctx, query.Host, resolver.ProxyServerHostResolver)
	default:
		return resolver.LookupIPWithResolver(ctx, query.Host, resolver.ProxyServerHostResolver)
	}
}

func exchangeDNS(ctx context.Context, host string, qtype uint16) (*D.Msg, error) {
	r := resolver.ProxyServerHostResolver
	if r == nil || !r.Invalid() {
		r = resolver.SystemResolver
	}
	if r == nil {
		return nil, fmt.Errorf("easytier: DNS resolver is unavailable")
	}
	request := new(D.Msg)
	request.SetQuestion(D.Fqdn(host), qtype)
	reply, err := r.ExchangeContext(ctx, request)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, fmt.Errorf("easytier: empty DNS response for %q", host)
	}
	if reply.Rcode != D.RcodeSuccess {
		return nil, fmt.Errorf("easytier: DNS query for %q returned %s", host, D.RcodeToString[reply.Rcode])
	}
	return reply, nil
}

func (DNSResolver) LookupTXT(ctx context.Context, query platform.DNSQuery) (string, error) {
	reply, err := exchangeDNS(ctx, query.Host, D.TypeTXT)
	if err != nil {
		return "", err
	}
	for _, answer := range reply.Answer {
		if txt, ok := answer.(*D.TXT); ok {
			return strings.Join(txt.Txt, ""), nil
		}
	}
	return "", fmt.Errorf("easytier: DNS TXT query for %q returned no records", query.Host)
}

func (DNSResolver) LookupSRV(ctx context.Context, query platform.DNSQuery) ([]*net.SRV, error) {
	reply, err := exchangeDNS(ctx, query.Host, D.TypeSRV)
	if err != nil {
		return nil, err
	}
	var records []*net.SRV
	for _, answer := range reply.Answer {
		if srv, ok := answer.(*D.SRV); ok {
			records = append(records, &net.SRV{Target: srv.Target, Port: srv.Port, Priority: srv.Priority, Weight: srv.Weight})
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("easytier: DNS SRV query for %q returned no records", query.Host)
	}
	return records, nil
}

// ConnectorEnvironment reports the local address used toward a remote UDP peer.
type ConnectorEnvironment struct {
	Dialer C.Dialer
}

func (e ConnectorEnvironment) LocalAddrForRemote(ctx context.Context, remote *net.UDPAddr, _ platform.SocketContext) (net.Addr, error) {
	if remote == nil {
		return nil, fmt.Errorf("easytier: missing remote address")
	}
	network := "udp"
	if remote.IP.To4() != nil {
		network = "udp4"
	} else if remote.IP.To16() != nil {
		network = "udp6"
	}
	conn, err := e.Dialer.DialContext(ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr(), nil
}
