package system

import (
	"net"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"

	"github.com/kr328/tun2socket/binding"
)

func handleTCP(conn net.Conn, endpoint *binding.Endpoint, tcpIn chan<- C.ConnContext) {
	src := &net.TCPAddr{
		IP:   endpoint.Source.IP,
		Port: int(endpoint.Source.Port),
		Zone: "",
	}

	dst := &net.TCPAddr{
		IP:   endpoint.Target.IP,
		Port: int(endpoint.Target.Port),
		Zone: "",
	}

	addrType := C.AtypIPv4
	if dst.IP.To4() == nil {
		addrType = C.AtypIPv6
	}

	metadata := &C.Metadata{
		NetWork:  C.TCP,
		Type:     C.TUN,
		SrcIP:    src.IP,
		DstIP:    dst.IP,
		SrcPort:  strconv.Itoa(src.Port),
		DstPort:  strconv.Itoa(dst.Port),
		AddrType: addrType,
		Host:     "",
	}

	//if c, ok := conn.(*net.TCPConn); ok {
	//	c.SetKeepAlive(true)
	//}
	tcpIn <- context.NewConnContext(conn, metadata)
}
