package inbound

import (
	"net"
	"net/netip"
	"strconv"

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

	if ip, port, err := parseAddr(conn.RemoteAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}
	if ip, port, err := parseAddr(conn.LocalAddr()); err == nil {
		metadata.InIP = ip
		metadata.InPort = port
	}

	return context.NewConnContext(conn, metadata)
}

func NewInner(conn net.Conn, address string) *context.ConnContext {
	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.DNSMode = C.DNSNormal
	metadata.Process = C.ClashName
	if h, port, err := net.SplitHostPort(address); err == nil {
		if port, err := strconv.ParseUint(port, 10, 16); err == nil {
			metadata.DstPort = uint16(port)
		}
		if ip, err := netip.ParseAddr(h); err == nil {
			metadata.DstIP = ip
		} else {
			metadata.Host = h
		}
	}

	return context.NewConnContext(conn, metadata)
}
