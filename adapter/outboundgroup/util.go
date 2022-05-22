package outboundgroup

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

func addrToMetadata(rawAddress string) (addr *C.Metadata, err error) {
	host, port, err := net.SplitHostPort(rawAddress)
	if err != nil {
		err = fmt.Errorf("addrToMetadata failed: %w", err)
		return
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		addr = &C.Metadata{
			AddrType: C.AtypDomainName,
			Host:     host,
			DstIP:    netip.Addr{},
			DstPort:  port,
		}
		err = nil
		return
	} else if ip.Is4() {
		addr = &C.Metadata{
			AddrType: C.AtypIPv4,
			Host:     "",
			DstIP:    ip,
			DstPort:  port,
		}
		return
	}

	addr = &C.Metadata{
		AddrType: C.AtypIPv6,
		Host:     "",
		DstIP:    ip,
		DstPort:  port,
	}
	return
}

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

type SelectAble interface {
	Set(string) error
}
