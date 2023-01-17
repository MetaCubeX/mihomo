package inbound

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/nnip"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

func parseSocksAddr(target socks5.Addr) *C.Metadata {
	metadata := &C.Metadata{}

	switch target[0] {
	case socks5.AtypDomainName:
		// trim for FQDN
		metadata.Host = strings.TrimRight(string(target[2:2+target[1]]), ".")
		metadata.DstPort = strconv.Itoa((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
	case socks5.AtypIPv4:
		metadata.DstIP = nnip.IpToAddr(net.IP(target[1 : 1+net.IPv4len]))
		metadata.DstPort = strconv.Itoa((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks5.AtypIPv6:
		ip6, _ := netip.AddrFromSlice(target[1 : 1+net.IPv6len])
		metadata.DstIP = ip6.Unmap()
		metadata.DstPort = strconv.Itoa((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}

	return metadata
}

func parseHTTPAddr(request *http.Request) *C.Metadata {
	host := request.URL.Hostname()
	port := request.URL.Port()
	if port == "" {
		port = "80"
	}

	// trim FQDN (#737)
	host = strings.TrimRight(host, ".")

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstIP:   netip.Addr{},
		DstPort: port,
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		metadata.DstIP = ip
	}

	return metadata
}

func parseAddr(addr net.Addr) (netip.Addr, string, error) {
	// Filter when net.Addr interface is nil
	if addr == nil {
		return netip.Addr{}, "", errors.New("nil addr")
	}
	if rawAddr, ok := addr.(interface{ RawAddr() net.Addr }); ok {
		ip, port, err := parseAddr(rawAddr.RawAddr())
		if err == nil {
			return ip, port, err
		}
	}
	addrStr := addr.String()
	host, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		return netip.Addr{}, "", err
	}

	ip, err := netip.ParseAddr(host)
	return ip, port, err
}
