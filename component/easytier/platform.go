package easytier

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

// Services wraps a mihomo dialer as EasyTier platform capabilities.
func Services(dialer C.Dialer) platform.Services {
	return platform.Services{
		Sockets:     SocketFactory{Dialer: dialer},
		DNS:         DNSResolver{},
		Environment: ConnectorEnvironment{Dialer: dialer},
	}
}

// SocketFactory creates sockets through mihomo's dialer.
//
// EasyTier BindDevice/SocketMark/reuse options are ignored so hole punching
// can bind local UDP ports. Interface, routing-mark, and dialer-proxy stay on
// the mihomo dialer. FakeTCP is not supported.
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
	address := ":0"
	if options.Bind.LocalAddr != nil {
		address = options.Bind.LocalAddr.String()
	}
	var lc net.ListenConfig
	return lc.Listen(ctx, tcpNetwork(options.Bind), address)
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

func (DNSResolver) LookupTXT(ctx context.Context, query platform.DNSQuery) (string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, query.Host)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("easytier: DNS TXT query for %q returned no records", query.Host)
	}
	return records[0], nil
}

func (DNSResolver) LookupSRV(ctx context.Context, query platform.DNSQuery) ([]*net.SRV, error) {
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", query.Host)
	return records, err
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
