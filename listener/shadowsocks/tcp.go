package shadowsocks

import (
	"net"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/shadowsocks/core"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Listener struct {
	closed       bool
	config       string
	listeners    []net.Listener
	udpListeners []*UDPListener
	pickCipher   core.Cipher
}

var _listener *Listener

func New(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (*Listener, error) {
	addr, cipher, password, err := parseSSURL(config)
	if err != nil {
		return nil, err
	}

	pickCipher, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}

	sl := &Listener{false, config, nil, nil, pickCipher}
	_listener = sl

	for _, addr := range strings.Split(addr, ",") {
		addr := addr

		//UDP
		ul, err := NewUDP(addr, pickCipher, udpIn)
		if err != nil {
			return nil, err
		}
		sl.udpListeners = append(sl.udpListeners, ul)

		//TCP
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			log.Infoln("ShadowSocks proxy listening at: %s", l.Addr().String())
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

func (l *Listener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
	for _, lis := range l.udpListeners {
		_ = lis.Close()
	}
}

func (l *Listener) Config() string {
	return l.config
}

func (l *Listener) HandleConn(conn net.Conn, in chan<- C.ConnContext) {
	conn = l.pickCipher.StreamConn(conn)

	target, err := socks5.ReadAddr(conn, make([]byte, socks5.MaxAddrLen))
	if err != nil {
		_ = conn.Close()
		return
	}
	in <- inbound.NewSocket(target, conn, C.SHADOWSOCKS)
}

func HandleShadowSocks(conn net.Conn, in chan<- C.ConnContext) bool {
	if _listener != nil && _listener.pickCipher != nil {
		go _listener.HandleConn(conn, in)
		return true
	}
	return false
}
