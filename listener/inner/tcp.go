package inner

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

var tunnel C.Tunnel

func New(t C.Tunnel) {
	tunnel = t
}

func HandleTcp(address string, proxy string) (conn net.Conn, err error) {
	if tunnel == nil {
		return nil, errors.New("tcp uninitialized")
	}
	// executor Parsed
	conn1, conn2 := N.Pipe()

	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.DNSMode = C.DNSNormal
	metadata.Process = C.MihomoName
	if proxy != "" {
		metadata.SpecialProxy = proxy
	}
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

	go tunnel.HandleTCPConn(conn2, metadata)
	return conn1, nil
}
