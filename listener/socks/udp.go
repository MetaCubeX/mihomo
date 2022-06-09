package socks

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/sockopt"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
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

	if err := sockopt.UDPReuseaddr(l.(*net.UDPConn)); err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}

	sl := &UDPListener{
		packetConn: l,
		addr:       addr,
	}
	go func() {
		for {
			buffer := buf.NewPacket()
			n, remoteAddr, err := l.ReadFrom(buffer.FreeBytes())
			if err != nil {
				buffer.Release()
				if sl.closed {
					break
				}
				continue
			}
			buffer.Extend(n)
			handleSocksUDP(l, in, buffer, remoteAddr)
		}
	}()

	return sl, nil
}

func handleSocksUDP(pc net.PacketConn, in chan<- *inbound.PacketAdapter, buffer *buf.Buffer, addr net.Addr) {
	buffer.Advance(3)
	target, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		// Unresolved UDP packet, return buffer to the pool
		buffer.Release()
		return
	}
	packet := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: buffer,
	}
	select {
	case in <- inbound.NewPacket(target, packet, C.SOCKS5):
	default:
	}
}
