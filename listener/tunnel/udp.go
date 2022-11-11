package tunnel

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
)

type UdpListener struct {
	closed    bool
	config    string
	listeners []net.PacketConn
}

func NewUdp(config string, in chan<- *inbound.PacketAdapter) (*UdpListener, error) {
	ul := &UdpListener{false, config, nil}
	pl := PairList{}
	err := pl.Set(config)
	if err != nil {
		return nil, err
	}

	for _, p := range pl {
		addr := p[0]
		target := p[1]
		go func() {
			tgt := socks5.ParseAddr(target)
			if tgt == nil {
				log.Errorln("invalid target address %q", target)
				return
			}
			l, err := net.ListenPacket("udp", addr)
			if err != nil {
				return
			}
			ul.listeners = append(ul.listeners, l)
			log.Infoln("Udp tunnel %s <-> %s", l.LocalAddr().String(), target)
			for {
				buf := pool.Get(pool.RelayBufferSize)
				n, remoteAddr, err := l.ReadFrom(buf)
				if err != nil {
					pool.Put(buf)
					if ul.closed {
						break
					}
					continue
				}
				packet := &packet{
					pc:      l,
					rAddr:   remoteAddr,
					payload: buf[:n],
					bufRef:  buf,
				}
				select {
				case in <- inbound.NewPacket(tgt, packet, C.UDPTUN):
				default:
				}

			}
		}()
	}

	return ul, nil
}

func (l *UdpListener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
}

func (l *UdpListener) Config() string {
	return l.config
}
