package lwip

import (
	"io"
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/yaling888/go-lwip"
)

type udpPacket struct {
	source  *net.UDPAddr
	payload []byte
	sender  golwip.UDPConn
}

func (u *udpPacket) Data() []byte {
	return u.payload
}

func (u *udpPacket) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	_, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, io.ErrClosedPipe
	}

	return u.sender.WriteFrom(b, u.source)
}

func (u *udpPacket) Drop() {
}

func (u *udpPacket) LocalAddr() net.Addr {
	return u.source
}

type udpHandler struct {
	dnsIP net.IP
	udpIn chan<- *inbound.PacketAdapter
}

func newUDPHandler(dnsIP net.IP, udpIn chan<- *inbound.PacketAdapter) golwip.UDPConnHandler {
	return &udpHandler{dnsIP, udpIn}
}

func (h *udpHandler) Connect(golwip.UDPConn, *net.UDPAddr) error {
	return nil
}

func (h *udpHandler) ReceiveTo(conn golwip.UDPConn, data []byte, addr *net.UDPAddr) error {
	if shouldHijackDns(h.dnsIP, addr.IP, addr.Port) {
		hijackUDPDns(conn, data, addr)
		log.Debugln("[TUN] hijack dns udp: %s:%d", addr.IP.String(), addr.Port)
		return nil
	}

	packet := &udpPacket{
		source:  conn.LocalAddr(),
		payload: data,
		sender:  conn,
	}

	go func(addr *net.UDPAddr, packet *udpPacket) {
		select {
		case h.udpIn <- inbound.NewPacket(socks5.ParseAddrToSocksAddr(addr), packet, C.TUN):
		default:
		}
	}(addr, packet)

	return nil
}
