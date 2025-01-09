package sing_shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	embedSS "github.com/metacubex/mihomo/listener/shadowsocks"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type Listener struct {
	closed       bool
	config       LC.ShadowsocksServer
	listeners    []net.Listener
	udpListeners []net.PacketConn
	service      shadowsocks.Service
}

var _listener *Listener

func New(config LC.ShadowsocksServer, tunnel C.Tunnel, additions ...inbound.Addition) (C.MultiAddrListener, error) {
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

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.SHADOWSOCKS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	sl = &Listener{false, config, nil, nil, nil}

	switch {
	case config.Cipher == shadowsocks.MethodNone:
		sl.service = shadowsocks.NewNoneService(udpTimeout, h)
	case common.Contains(shadowaead.List, config.Cipher):
		sl.service, err = shadowaead.NewService(config.Cipher, nil, config.Password, udpTimeout, h)
	case common.Contains(shadowaead_2022.List, config.Cipher):
		sl.service, err = shadowaead_2022.NewServiceWithPassword(config.Cipher, config.Password, udpTimeout, h, ntp.Now)
	default:
		err = fmt.Errorf("shadowsocks: unsupported method: %s", config.Cipher)
		return embedSS.New(config, tunnel, additions...)
	}
	if err != nil {
		return nil, err
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		if config.Udp {
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
				rwOptions := network.ReadWaitOptions{
					FrontHeadroom: network.CalculateFrontHeadroom(sl.service),
					RearHeadroom:  network.CalculateRearHeadroom(sl.service),
					MTU:           network.CalculateMTU(conn, sl.service),
				}
				readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn)
				if isReadWaiter {
					readWaiter.InitializeReadWaiter(rwOptions)
				}
				for {
					var (
						buff *buf.Buffer
						dest M.Socksaddr
						err  error
					)
					buff = nil // clear last loop status, avoid repeat release
					if isReadWaiter {
						buff, dest, err = readWaiter.WaitReadPacket()
					} else {
						buff = rwOptions.NewPacketBuffer()
						dest, err = conn.ReadPacket(buff)
						if buff != nil {
							rwOptions.PostReturn(buff)
						}
					}
					if err != nil {
						buff.Release()
						if sl.closed {
							break
						}
						continue
					}
					_ = sl.service.NewPacket(context.TODO(), conn, buff, M.Metadata{
						Protocol: "shadowsocks",
						Source:   dest,
					})
				}
			}()
		}

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

				go sl.HandleConn(c, tunnel)
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

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	ctx := sing.WithAdditions(context.TODO(), additions...)
	err := l.service.NewConnection(ctx, conn, M.Metadata{
		Protocol: "shadowsocks",
		Source:   M.ParseSocksaddr(conn.RemoteAddr().String()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleShadowSocks(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return embedSS.HandleShadowSocks(conn, tunnel, additions...)
}
