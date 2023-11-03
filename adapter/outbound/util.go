package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

var (
	globalClientSessionCache tls.ClientSessionCache
	once                     sync.Once
)

func getClientSessionCache() tls.ClientSessionCache {
	once.Do(func() {
		globalClientSessionCache = tls.NewLRUClientSessionCache(128)
	})
	return globalClientSessionCache
}

func serializesSocksAddr(metadata *C.Metadata) []byte {
	var buf [][]byte
	addrType := metadata.AddrType()
	aType := uint8(addrType)
	p := uint(metadata.DstPort)
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

var rateStringRegexp = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

func StringToBps(s string) uint64 {
	if s == "" {
		return 0
	}

	// when have not unit, use Mbps
	if v, err := strconv.Atoi(s); err == nil {
		return StringToBps(fmt.Sprintf("%d Mbps", v))
	}

	m := rateStringRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	var n uint64
	switch m[2] {
	case "K":
		n = 1 << 10
	case "M":
		n = 1 << 20
	case "G":
		n = 1 << 30
	case "T":
		n = 1 << 40
	default:
		n = 1
	}
	v, _ := strconv.ParseUint(m[1], 10, 64)
	n = v * n
	if m[3] == "b" {
		// Bits, need to convert to bytes
		n = n >> 3
	}
	return n
}
