package adapters

import (
	"net"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
	"github.com/riobard/go-shadowsocks2/socks"
)

func parseSocksAddr(target socks.Addr) *C.Addr {
	var host, port string
	var ip net.IP

	switch target[0] {
	case socks.AtypDomainName:
		host = string(target[2 : 2+target[1]])
		port = strconv.Itoa((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
		ipAddr, err := net.ResolveIPAddr("ip", host)
		if err == nil {
			ip = ipAddr.IP
		}
	case socks.AtypIPv4:
		ip = net.IP(target[1 : 1+net.IPv4len])
		port = strconv.Itoa((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks.AtypIPv6:
		ip = net.IP(target[1 : 1+net.IPv6len])
		port = strconv.Itoa((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}

	return &C.Addr{
		NetWork:  C.TCP,
		AddrType: int(target[0]),
		Host:     host,
		IP:       &ip,
		Port:     port,
	}
}

func parseHttpAddr(target string) *C.Addr {
	host, port, _ := net.SplitHostPort(target)
	ipAddr, err := net.ResolveIPAddr("ip", host)
	var resolveIP *net.IP
	if err == nil {
		resolveIP = &ipAddr.IP
	}

	var addType int
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		addType = socks.AtypDomainName
	case ip.To4() == nil:
		addType = socks.AtypIPv6
	default:
		addType = socks.AtypIPv4
	}

	return &C.Addr{
		NetWork:  C.TCP,
		AddrType: addType,
		Host:     host,
		IP:       resolveIP,
		Port:     port,
	}
}
