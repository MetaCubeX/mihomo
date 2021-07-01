package system

import (
	"net"
	"strconv"

	"github.com/kr328/tun2socket/binding"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
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

	metadata := &C.Metadata{
		NetWork:  C.TCP,
		Type:     C.TUN,
		SrcIP:    src.IP,
		DstIP:    dst.IP,
		SrcPort:  strconv.Itoa(src.Port),
		DstPort:  strconv.Itoa(dst.Port),
		AddrType: C.AtypIPv4,
		Host:     "",
	}

	tcpIn <- context.NewConnContext(conn, metadata)
}
