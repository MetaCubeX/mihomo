package inbound

import (
	"net"
	"net/netip"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewSocket receive TCP inbound and return ConnContext
func NewSocket(target socks5.Addr, conn net.Conn, source C.Type, additions ...Addition) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = source
	for _, addition := range additions {
		addition.Apply(metadata)
	}

	remoteAddr := conn.RemoteAddr()

	// Filter when net.Addr interface is nil
	if remoteAddr != nil {
		if ip, port, err := parseAddr(remoteAddr.String()); err == nil {
			metadata.SrcIP = ip
			metadata.SrcPort = port
		}
	}
	localAddr := conn.LocalAddr()
	// Filter when net.Addr interface is nil
	if localAddr != nil {
		if ip, port, err := parseAddr(localAddr.String()); err == nil {
			metadata.InIP = ip
			metadata.InPort = port
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
	metadata.Process = C.ClashName
	if h, port, err := net.SplitHostPort(dst); err == nil {
		metadata.DstPort = port
		if host == "" {
			if ip, err := netip.ParseAddr(h); err == nil {
				metadata.DstIP = ip
			}
		}
	}

	return context.NewConnContext(conn, metadata)
}
