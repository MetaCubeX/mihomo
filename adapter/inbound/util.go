package inbound

import (
	"net"
	"net/netip"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http"
)

func parseSocksAddr(target socks5.Addr) *C.Metadata {
	metadata := &C.Metadata{}

	switch target[0] {
	case socks5.AtypDomainName:
		// Convert before arithmetic so long domain lengths cannot overflow a byte.
		domainEnd := 2 + int(target[1])
		// trim for FQDN
		metadata.Host = strings.TrimRight(string(target[2:domainEnd]), ".")
		metadata.DstPort = uint16(target[domainEnd])<<8 | uint16(target[domainEnd+1])
	case socks5.AtypIPv4:
		metadata.DstIP, _ = netip.AddrFromSlice(target[1 : 1+net.IPv4len])
		metadata.DstPort = uint16((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks5.AtypIPv6:
		metadata.DstIP, _ = netip.AddrFromSlice(target[1 : 1+net.IPv6len])
		metadata.DstPort = uint16((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}
	metadata.DstIP = metadata.DstIP.Unmap()

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

	metadata := &C.Metadata{}
	_ = metadata.SetRemoteAddress(net.JoinHostPort(host, port))
	return metadata
}

func prefixesContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	if len(prefixes) == 0 {
		return false
	}
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("") // netip.Prefix.Contains returns false if ip has an IPv6 zone
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
