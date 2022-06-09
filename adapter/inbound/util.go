package inbound

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/nnip"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
	M "github.com/sagernet/sing/common/metadata"
)

func socksAddrToMetadata(addr M.Socksaddr) *C.Metadata {
	metadata := &C.Metadata{}
	switch addr.Family() {
	case M.AddressFamilyIPv4:
		metadata.AddrType = C.AtypIPv4
		metadata.DstIP = addr.Addr
	case M.AddressFamilyIPv6:
		metadata.AddrType = C.AtypIPv6
		metadata.DstIP = addr.Addr
	case M.AddressFamilyFqdn:
		metadata.AddrType = C.AtypDomainName
		metadata.Host = addr.Fqdn
	}
	metadata.DstPort = strconv.Itoa(int(addr.Port))
	return metadata
}

func parseSocksAddr(target socks5.Addr) *C.Metadata {
	metadata := &C.Metadata{
		AddrType: int(target[0]),
	}

	switch target[0] {
	case socks5.AtypDomainName:
		// trim for FQDN
		metadata.Host = strings.TrimRight(string(target[2:2+target[1]]), ".")
		metadata.DstPort = strconv.Itoa((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
	case socks5.AtypIPv4:
		metadata.DstIP = nnip.IpToAddr(net.IP(target[1 : 1+net.IPv4len]))
		metadata.DstPort = strconv.Itoa((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks5.AtypIPv6:
		metadata.DstIP = nnip.IpToAddr(net.IP(target[1 : 1+net.IPv6len]))
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
		NetWork:  C.TCP,
		AddrType: C.AtypDomainName,
		Host:     host,
		DstIP:    netip.Addr{},
		DstPort:  port,
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		switch {
		case ip.Is6():
			metadata.AddrType = C.AtypIPv6
		default:
			metadata.AddrType = C.AtypIPv4
		}
		metadata.DstIP = ip
	}

	return metadata
}

func parseAddr(addr string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.Addr{}, "", err
	}

	ip, err := netip.ParseAddr(host)
	return ip, port, err
}
