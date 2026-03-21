package tunnel

import (
	"fmt"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
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

func NewUDP(addr, target, proxy string, tunnel C.Tunnel, additions ...inbound.Addition) (*PacketConn, error) {
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

	if proxy != "" {
		additions = append([]inbound.Addition{inbound.WithSpecialProxy(proxy)}, additions...)
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
			sl.handleUDP(l, tunnel, buf[:n], remoteAddr, additions...)
		}
	}()

	return sl, nil
}

func (l *PacketConn) handleUDP(pc net.PacketConn, tunnel C.Tunnel, buf []byte, addr net.Addr, additions ...inbound.Addition) {
	cPacket := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: buf,
	}

	tunnel.HandleUDPPacket(inbound.NewPacket(l.target, cPacket, C.TUNNEL, additions...))
}
