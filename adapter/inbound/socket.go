package inbound

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewSocket receive TCP inbound and return ConnContext
func NewSocket(target socks5.Addr, conn net.Conn, source C.Type) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = source
	remoteAddr := conn.RemoteAddr()
	// Filter when net.Addr interface is nil
	if remoteAddr != nil {
		if ip, port, err := parseAddr(remoteAddr.String()); err == nil {
			metadata.SrcIP = ip
			metadata.SrcPort = port
		}
	}

	return context.NewConnContext(conn, metadata)
}

func NewInner(conn net.Conn, dst string, host string) *context.ConnContext {
	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.DNSMode = C.DNSMapping
	metadata.Host = host
	metadata.AddrType = C.AtypDomainName
	metadata.Process = C.ClashName
	if ip, port, err := parseAddr(dst); err == nil {
		metadata.DstPort = port
		if host == "" {
			metadata.DstIP = ip
			if ip.Is4() {
				metadata.AddrType = C.AtypIPv6
			} else {
				metadata.AddrType = C.AtypIPv4
			}
		}
	}

	return context.NewConnContext(conn, metadata)
}
