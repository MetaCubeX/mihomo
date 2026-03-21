package inner

import (
	"errors"
	"net"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

var tunnel C.Tunnel

func New(t C.Tunnel) {
	tunnel = t
}

func GetTunnel() C.Tunnel {
	return tunnel
}

func HandleTcp(tunnel C.Tunnel, address string, proxy string) (conn net.Conn, err error) {
	if tunnel == nil {
		return nil, errors.New("tunnel uninitialized")
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
	if err = metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}

	go tunnel.HandleTCPConn(conn2, metadata)
	return conn1, nil
}
