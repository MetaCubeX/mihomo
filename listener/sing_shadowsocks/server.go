package sing_shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/sockopt"
	C "github.com/Dreamacro/clash/constant"
	embedSS "github.com/Dreamacro/clash/listener/shadowsocks"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/metadata"
)

type Listener struct {
	closed       bool
	config       string
	listeners    []net.Listener
	udpListeners []net.PacketConn
	service      shadowsocks.Service
}

var _listener *Listener

func New(config string, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) (C.AdvanceListener, error) {
	addr, cipher, password, err := embedSS.ParseSSURL(config)
	if err != nil {
		return nil, err
	}
	udpTimeout := int64(sing.UDPTimeout.Seconds())

	h := &sing.ListenerHandler{
		TcpIn: tcpIn,
		UdpIn: udpIn,
		Type:  C.SHADOWSOCKS,
	}

	sl := &Listener{false, config, nil, nil, nil}

	switch {
	case cipher == shadowsocks.MethodNone:
		sl.service = shadowsocks.NewNoneService(udpTimeout, h)
	case common.Contains(shadowaead.List, cipher):
		sl.service, err = shadowaead.NewService(cipher, nil, password, udpTimeout, h)
	case common.Contains(shadowaead_2022.List, cipher):
		sl.service, err = shadowaead_2022.NewServiceWithPassword(cipher, password, udpTimeout, h)
	default:
		err = fmt.Errorf("shadowsocks: unsupported method: %s", cipher)
		return embedSS.New(config, tcpIn, udpIn)
	}
	if err != nil {
		return nil, err
	}

	_listener = sl

	for _, addr := range strings.Split(addr, ",") {
		addr := addr

		//UDP
		ul, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, err
		}

		err = sockopt.UDPReuseaddr(ul.(*net.UDPConn))
		if err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		sl.udpListeners = append(sl.udpListeners, ul)

		go func() {
			conn := bufio.NewPacketConn(ul)
			for {
				buff := buf.NewPacket()
				remoteAddr, err := conn.ReadPacket(buff)
				if err != nil {
					buff.Release()
					if sl.closed {
						break
					}
					continue
				}
				_ = sl.service.NewPacket(context.TODO(), conn, buff, metadata.Metadata{
					Protocol: "shadowsocks",
					Source:   remoteAddr,
				})
			}
		}()

		//TCP
		l, err := inbound.Listen("tcp", addr)
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
	err := l.service.NewConnection(context.TODO(), conn, metadata.Metadata{
		Protocol: "shadowsocks",
		Source:   metadata.ParseSocksaddr(conn.RemoteAddr().String()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleShadowSocks(conn net.Conn, in chan<- C.ConnContext) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn, in)
		return true
	}
	return embedSS.HandleShadowSocks(conn, in)
}
