package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	xtls "github.com/xtls/go"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

var (
	globalClientSessionCache  tls.ClientSessionCache
	globalClientXSessionCache xtls.ClientSessionCache
	once                      sync.Once
)

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

func getClientSessionCache() tls.ClientSessionCache {
	once.Do(func() {
		globalClientSessionCache = tls.NewLRUClientSessionCache(128)
	})
	return globalClientSessionCache
}

func getClientXSessionCache() xtls.ClientSessionCache {
	once.Do(func() {
		globalClientXSessionCache = xtls.NewLRUClientSessionCache(128)
	})
	return globalClientXSessionCache
}

func serializesSocksAddr(metadata *C.Metadata) []byte {
	var buf [][]byte
	addrType := metadata.AddrType()
	aType := uint8(addrType)
	p, _ := strconv.ParseUint(metadata.DstPort, 10, 16)
	port := []byte{uint8(p >> 8), uint8(p & 0xff)}
	switch addrType {
	case socks5.AtypDomainName:
		lenM := uint8(len(metadata.Host))
		host := []byte(metadata.Host)
		buf = [][]byte{{aType, lenM}, host, port}
	case socks5.AtypIPv4:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{aType}, host, port}
	case socks5.AtypIPv6:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{aType}, host, port}
	}
	return bytes.Join(buf, nil)
}

func resolveUDPAddr(ctx context.Context, network, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ip, err := resolver.ResolveProxyServerHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr(network, net.JoinHostPort(ip.String(), port))
}

func resolveUDPAddrWithPrefer(ctx context.Context, network, address string, prefer C.DNSPrefer) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ip netip.Addr
	var fallback netip.Addr
	switch prefer {
	case C.IPv4Only:
		ip, err = resolver.ResolveIPv4ProxyServerHost(ctx, host)
	case C.IPv6Only:
		ip, err = resolver.ResolveIPv6ProxyServerHost(ctx, host)
	case C.IPv6Prefer:
		var ips []netip.Addr
		ips, err = resolver.LookupIPProxyServerHost(ctx, host)
		if err == nil {
			for _, addr := range ips {
				if addr.Is6() {
					ip = addr
					break
				} else {
					if !fallback.IsValid() {
						fallback = addr
					}
				}
			}
		}
	default:
		// C.IPv4Prefer, C.DualStack and other
		var ips []netip.Addr
		ips, err = resolver.LookupIPProxyServerHost(ctx, host)
		if err == nil {
			for _, addr := range ips {
				if addr.Is4() {
					ip = addr
					break
				} else {
					if !fallback.IsValid() {
						fallback = addr
					}
				}
			}

		}
	}

	if !ip.IsValid() && fallback.IsValid() {
		ip = fallback
	}

	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr(network, net.JoinHostPort(ip.String(), port))
}

func safeConnClose(c net.Conn, err error) {
	if err != nil && c != nil {
		_ = c.Close()
	}
}
