package shadowsocks

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/common/sockopt"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/shadowsocks/core"
	"github.com/Dreamacro/clash/transport/socks5"
)

type UDPListener struct {
	packetConn net.PacketConn
	closed     bool
}

func NewUDP(addr string, pickCipher core.Cipher, in chan<- C.PacketAdapter) (*UDPListener, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	err = sockopt.UDPReuseaddr(l.(*net.UDPConn))
	if err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}

	sl := &UDPListener{l, false}
	conn := pickCipher.PacketConn(l)
	go func() {
		for {
			buf := pool.Get(pool.RelayBufferSize)
			n, remoteAddr, err := conn.ReadFrom(buf)
			if err != nil {
				pool.Put(buf)
				if sl.closed {
					break
				}
				continue
			}
			handleSocksUDP(conn, in, buf[:n], remoteAddr)
		}
	}()

	return sl, nil
}

func (l *UDPListener) Close() error {
	l.closed = true
	return l.packetConn.Close()
}

func (l *UDPListener) LocalAddr() net.Addr {
	return l.packetConn.LocalAddr()
}

func handleSocksUDP(pc net.PacketConn, in chan<- C.PacketAdapter, buf []byte, addr net.Addr) {
	tgtAddr := socks5.SplitAddr(buf)
	if tgtAddr == nil {
		// Unresolved UDP packet, return buffer to the pool
		pool.Put(buf)
		return
	}
	target := socks5.ParseAddr(tgtAddr.String())
	payload := buf[len(tgtAddr):]

	packet := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: payload,
		bufRef:  buf,
	}
	select {
	case in <- inbound.NewPacket(target, packet, C.SHADOWSOCKS):
	default:
	}
}
