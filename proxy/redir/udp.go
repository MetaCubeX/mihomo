package redir

import (
	"net"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
)

type RedirUDPListener struct {
	net.PacketConn
	address string
	closed  bool
}

func NewRedirUDPProxy(addr string) (*RedirUDPListener, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	rl := &RedirUDPListener{l, addr, false}

	c := l.(*net.UDPConn)

	err = setsockopt(c, addr)
	if err != nil {
		return nil, err
	}

	go func() {
		oob := make([]byte, 1024)
		for {
			buf := pool.BufPool.Get().([]byte)

			n, oobn, _, remoteAddr, err := c.ReadMsgUDP(buf, oob)
			if err != nil {
				pool.BufPool.Put(buf[:cap(buf)])
				if rl.closed {
					break
				}
				continue
			}

			origDst, err := getOrigDst(oob, oobn)
			if err != nil {
				continue
			}
			handleRedirUDP(l, buf[:n], remoteAddr, origDst)
		}
	}()

	return rl, nil
}

func (l *RedirUDPListener) Close() error {
	l.closed = true
	return l.PacketConn.Close()
}

func (l *RedirUDPListener) Address() string {
	return l.address
}

func handleRedirUDP(pc net.PacketConn, buf []byte, addr *net.UDPAddr, origDst *net.UDPAddr) {
	target := socks5.ParseAddrToSocksAddr(origDst)

	packet := &fakeConn{
		PacketConn: pc,
		origDst:    origDst,
		rAddr:      addr,
		buf:        buf,
	}
	tunnel.AddPacket(adapters.NewPacket(target, packet, C.REDIR))
}
