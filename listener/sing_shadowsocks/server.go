package sing_shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/sockopt"
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	embedSS "github.com/Dreamacro/clash/listener/shadowsocks"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/metadata"
)

type Listener struct {
	closed       bool
	config       LC.ShadowsocksServer
	listeners    []net.Listener
	udpListeners []net.PacketConn
	service      shadowsocks.Service
}

var _listener *Listener

func New(config LC.ShadowsocksServer, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter, additions ...inbound.Addition) (C.MultiAddrListener, error) {
	var sl *Listener
	var err error
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SHADOWSOCKS"),
			inbound.WithSpecialRules(""),
		}
		defer func() {
			_listener = sl
		}()
	}

	udpTimeout := int64(sing.UDPTimeout.Seconds())

	h := &sing.ListenerHandler{
		TcpIn:     tcpIn,
		UdpIn:     udpIn,
		Type:      C.SHADOWSOCKS,
		Additions: additions,
	}

	sl = &Listener{false, config, nil, nil, nil}

	switch {
	case config.Cipher == shadowsocks.MethodNone:
		sl.service = shadowsocks.NewNoneService(udpTimeout, h)
	case common.Contains(shadowaead.List, config.Cipher):
		sl.service, err = shadowaead.NewService(config.Cipher, nil, config.Password, udpTimeout, h)
	case common.Contains(shadowaead_2022.List, config.Cipher):
		sl.service, err = shadowaead_2022.NewServiceWithPassword(config.Cipher, config.Password, udpTimeout, h)
	default:
		err = fmt.Errorf("shadowsocks: unsupported method: %s", config.Cipher)
		return embedSS.New(config, tcpIn, udpIn)
	}
	if err != nil {
		return nil, err
	}

	for _, addr := range strings.Split(config.Listen, ",") {
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
	l.closed = true
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
	ctx := sing.WithAdditions(context.TODO(), additions...)
	err := l.service.NewConnection(ctx, conn, metadata.Metadata{
		Protocol: "shadowsocks",
		Source:   metadata.ParseSocksaddr(conn.RemoteAddr().String()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleShadowSocks(conn net.Conn, in chan<- C.ConnContext, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn, in, additions...)
		return true
	}
	return embedSS.HandleShadowSocks(conn, in, additions...)
}
