package lwip

import (
	"net"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
	"github.com/yaling888/go-lwip"
)

type tcpHandler struct {
	dnsIP net.IP
	tcpIn chan<- C.ConnContext
}

func newTCPHandler(dnsIP net.IP, tcpIn chan<- C.ConnContext) golwip.TCPConnHandler {
	return &tcpHandler{dnsIP, tcpIn}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	if shouldHijackDns(h.dnsIP, target.IP, target.Port) {
		hijackTCPDns(conn)
		log.Debugln("[TUN] hijack dns tcp: %s:%d", target.IP.String(), target.Port)
		return nil
	}

	if conn.RemoteAddr() == nil {
		_ = conn.Close()
		return nil
	}

	src, _ := conn.LocalAddr().(*net.TCPAddr)
	dst, _ := conn.RemoteAddr().(*net.TCPAddr)

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

	go func(conn net.Conn, metadata *C.Metadata) {
		//if c, ok := conn.(*net.TCPConn); ok {
		//	c.SetKeepAlive(true)
		//}
		h.tcpIn <- context.NewConnContext(conn, metadata)
	}(conn, metadata)

	return nil
}
