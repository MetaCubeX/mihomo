package constant

import (
	"net"
)

// Socks addr type
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// Addr is used to store connection address
type Addr struct {
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
