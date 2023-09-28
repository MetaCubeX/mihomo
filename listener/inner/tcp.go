package inner

import (
	"errors"
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
)

var tunnel C.Tunnel

func New(t C.Tunnel) {
	tunnel = t
}

func HandleTcp(address string) (conn net.Conn, err error) {
	if tunnel == nil {
		return nil, errors.New("tcp uninitialized")
	}
	// executor Parsed
	conn1, conn2 := net.Pipe()
	context := inbound.NewInner(conn2, address)
	go tunnel.HandleTCPConn(context)
	return conn1, nil
}
