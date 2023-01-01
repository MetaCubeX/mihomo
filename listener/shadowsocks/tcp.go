package shadowsocks

import (
	"net"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/transport/shadowsocks/core"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Listener struct {
	closed       bool
	config       LC.ShadowsocksServer
	listeners    []net.Listener
	udpListeners []*UDPListener
	pickCipher   core.Cipher
}

var _listener *Listener

func New(config LC.ShadowsocksServer, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) (*Listener, error) {
	pickCipher, err := core.PickCipher(config.Cipher, nil, config.Password)
	if err != nil {
		return nil, err
	}

	sl := &Listener{false, config, nil, nil, pickCipher}
	_listener = sl

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//UDP
		ul, err := NewUDP(addr, pickCipher, udpIn)
		if err != nil {
			return nil, err
		}
		sl.udpListeners = append(sl.udpListeners, ul)

		//TCP
		l, err := inbound.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)
				go sl.HandleConn(c, tcpIn)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	for _, lis := range l.udpListeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, in chan<- C.ConnContext, additions ...inbound.Addition) {
	conn = l.pickCipher.StreamConn(conn)

	target, err := socks5.ReadAddr(conn, make([]byte, socks5.MaxAddrLen))
	if err != nil {
		_ = conn.Close()
		return
	}
	in <- inbound.NewSocket(target, conn, C.SHADOWSOCKS, additions...)
}

func HandleShadowSocks(conn net.Conn, in chan<- C.ConnContext, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.pickCipher != nil {
		go _listener.HandleConn(conn, in, additions...)
		return true
	}
	return false
}
