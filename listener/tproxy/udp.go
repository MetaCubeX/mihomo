package tproxy

import (
	"net"
	"net/netip"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
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
			buf := pool.Get(pool.UDPBufferSize)
			n, oobn, _, lAddr, err := c.ReadMsgUDPAddrPort(buf, oob)
			if err != nil {
				pool.Put(buf)
				if rl.closed {
					break
				}
				continue
			}

			rAddr, err := getOrigDst(oob[:oobn])
			if err != nil {
				continue
			}

			if rAddr.Addr().Is4() {
				// try to unmap 4in6 address
				lAddr = netip.AddrPortFrom(lAddr.Addr().Unmap(), lAddr.Port())
			}
			handlePacketConn(in, buf[:n], lAddr, rAddr)
		}
	}()

	return rl, nil
}

func handlePacketConn(in chan<- *inbound.PacketAdapter, buf []byte, lAddr, rAddr netip.AddrPort) {
	target := socks5.AddrFromStdAddrPort(rAddr)
	pkt := &packet{
		lAddr: lAddr,
		buf:   buf,
	}
	select {
	case in <- inbound.NewPacket(target, pkt, C.TPROXY):
	default:
	}
}
