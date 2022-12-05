package tunnel

import (
	"fmt"
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

type PacketConn struct {
	conn   net.PacketConn
	addr   string
	target socks5.Addr
	proxy  string
	closed bool
}

// RawAddress implements C.Listener
func (l *PacketConn) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *PacketConn) Address() string {
	return l.conn.LocalAddr().String()
}

// Close implements C.Listener
func (l *PacketConn) Close() error {
	l.closed = true
	return l.conn.Close()
}

func NewUDP(addr, target, proxy string, in chan<- C.PacketAdapter, additions ...inbound.Addition) (*PacketConn, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	targetAddr := socks5.ParseAddr(target)
	if targetAddr == nil {
		return nil, fmt.Errorf("invalid target address %s", target)
	}

	sl := &PacketConn{
		conn:   l,
		target: targetAddr,
		proxy:  proxy,
		addr:   addr,
	}
	go func() {
		for {
			buf := pool.Get(pool.UDPBufferSize)
			n, remoteAddr, err := l.ReadFrom(buf)
			if err != nil {
				pool.Put(buf)
				if sl.closed {
					break
				}
				continue
			}
			sl.handleUDP(l, in, buf[:n], remoteAddr, additions...)
		}
	}()

	return sl, nil
}

func (l *PacketConn) handleUDP(pc net.PacketConn, in chan<- C.PacketAdapter, buf []byte, addr net.Addr, additions ...inbound.Addition) {
	packet := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: buf,
	}

	ctx := inbound.NewPacket(l.target, packet, C.TUNNEL, additions...)
	ctx.Metadata().SpecialProxy = l.proxy
	select {
	case in <- ctx:
	default:
	}
}
