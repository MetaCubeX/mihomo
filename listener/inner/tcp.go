package inner

import (
	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"net"
)

var tcpIn chan<- C.ConnContext

func New(in chan<- C.ConnContext) {
	tcpIn = in
}

func HandleTcp(dst string, host string) net.Conn {
	conn1, conn2 := net.Pipe()
	context := inbound.NewInner(conn2, dst, host)
	tcpIn <- context
	return conn1
}
