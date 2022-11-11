package tunnel

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Listener struct {
	closed    bool
	config    string
	listeners []net.Listener
}

func New(config string, in chan<- C.ConnContext) (*Listener, error) {
	tl := &Listener{false, config, nil}
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
			l, err := net.Listen("tcp", addr)
			if err != nil {
				return
			}
			tl.listeners = append(tl.listeners, l)
			log.Infoln("TCP tunnel %s <-> %s", l.Addr().String(), target)
			for {
				c, err := l.Accept()
				if err != nil {
					if tl.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)

				in <- inbound.NewSocket(tgt, c, C.TCPTUN)
			}
		}()
	}

	return tl, nil
}

func (l *Listener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
}

func (l *Listener) Config() string {
	return l.config
}
