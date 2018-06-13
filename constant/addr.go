package constant

import (
	"net"
)

// Socks addr type
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4

	TCP = iota
	UDP
)

type NetWork int

func (n *NetWork) String() string {
	if *n == TCP {
		return "tcp"
	}
	return "udp"
}

// Addr is used to store connection address
type Addr struct {
	NetWork  NetWork
	AddrType int
	Host     string
	IP       *net.IP
	Port     string
}

func (addr *Addr) String() string {
	if addr.Host == "" {
		return addr.IP.String()
	}
	return addr.Host
}
