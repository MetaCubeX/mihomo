package tproxy

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type UDPListener struct {
	packetConn net.PacketConn
	addr       string
	closed     bool
}

// RawAddress implements C.Listener
func (l *UDPListener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *UDPListener) Address() string {
	return l.packetConn.LocalAddr().String()
}

// Close implements C.Listener
func (l *UDPListener) Close() error {
	l.closed = true
	return l.packetConn.Close()
}

func NewUDP(addr string, in chan<- *inbound.PacketAdapter) (*UDPListener, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	rl := &UDPListener{
		packetConn: l,
		addr:       addr,
	}

	c := l.(*net.UDPConn)

	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	err = setsockopt(rc, addr)
	if err != nil {
		return nil, err
	}

	go func() {
		oob := make([]byte, 1024)
		for {
			buffer := buf.NewPacket()
			n, oobn, _, lAddr, err := c.ReadMsgUDP(buffer.FreeBytes(), oob)
			if err != nil {
				buffer.Release()
				if rl.closed {
					break
				}
				continue
			}

			rAddr, err := getOrigDst(oob, oobn)
			if err != nil {
				continue
			}
			buffer.Extend(n)
			handlePacketConn(l, in, buffer, lAddr, rAddr)
		}
	}()

	return rl, nil
}

func handlePacketConn(pc net.PacketConn, in chan<- *inbound.PacketAdapter, buf *buf.Buffer, lAddr *net.UDPAddr, rAddr *net.UDPAddr) {
	pkt := &packet{
		lAddr: lAddr,
		buf:   buf,
	}
	select {
	case in <- inbound.NewPacket(M.SocksaddrFromNet(rAddr), pkt, C.TPROXY):
	default:
	}
}
