package outbound

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

func serializesSocksAddr(metadata *C.Metadata) []byte {
	var buf [][]byte
	addrType := metadata.AddrType()
	p := uint(metadata.DstPort)
	port := []byte{uint8(p >> 8), uint8(p & 0xff)}
	switch addrType {
	case C.AtypDomainName:
		lenM := uint8(len(metadata.Host))
		host := []byte(metadata.Host)
		buf = [][]byte{{socks5.AtypDomainName, lenM}, host, port}
	case C.AtypIPv4:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{socks5.AtypIPv4}, host, port}
	case C.AtypIPv6:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{socks5.AtypIPv6}, host, port}
	}
	return bytes.Join(buf, nil)
}

func resolveUDPAddr(ctx context.Context, network, address string, prefer C.DNSPrefer) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ip netip.Addr
	switch prefer {
	case C.IPv4Only:
		ip, err = resolver.ResolveIPv4WithResolver(ctx, host, resolver.ProxyServerHostResolver)
	case C.IPv6Only:
		ip, err = resolver.ResolveIPv6WithResolver(ctx, host, resolver.ProxyServerHostResolver)
	case C.IPv6Prefer:
		ip, err = resolver.ResolveIPPrefer6WithResolver(ctx, host, resolver.ProxyServerHostResolver)
	default:
		ip, err = resolver.ResolveIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
	}

	if err != nil {
		return nil, err
	}

	ip, port = resolver.LookupIP4P(ip, port)

	var uint16Port uint16
	if port, err := strconv.ParseUint(port, 10, 16); err == nil {
		uint16Port = uint16(port)
	} else {
		return nil, err
	}
	// our resolver always unmap before return, so unneeded unmap at here
	// which is different with net.ResolveUDPAddr maybe return 4in6 address
	// 4in6 addresses can cause some strange effects on sing-based code
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16Port)), nil
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
	var n uint64 = 1
	switch m[2] {
	case "T":
		n *= 1000
		fallthrough
	case "G":
		n *= 1000
		fallthrough
	case "M":
		n *= 1000
		fallthrough
	case "K":
		n *= 1000
	}
	v, _ := strconv.ParseUint(m[1], 10, 64)
	n *= v
	if m[3] == "b" {
		// Bits, need to convert to bytes
		n /= 8
	}
	return n
}
