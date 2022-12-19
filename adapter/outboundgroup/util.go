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

	if ip, err := netip.ParseAddr(host); err != nil {
		addr = &C.Metadata{
			Host:    host,
			DstPort: port,
		}
	} else {
		addr = &C.Metadata{
			Host:    "",
			DstIP:   ip.Unmap(),
			DstPort: port,
		}
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
