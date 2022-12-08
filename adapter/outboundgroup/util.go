package outboundgroup

import (
	"net"
)

func tcpKeepAlive(c net.Conn) {
	//if tcp, ok := c.(*net.TCPConn); ok {
	//	_ = tcp.SetKeepAlive(true)
	//	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	//}
}

type SelectAble interface {
	Set(string) error
	ForceSet(name string)
}
