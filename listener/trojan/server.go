package trojan

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/sagernet/smux"
)

type Listener struct {
	closed     bool
	config     LC.TrojanServer
	listeners  []net.Listener
	keys       map[[trojan.KeyLength]byte]string
	pickCipher core.Cipher
	handler    *sing.ListenerHandler
}

func New(config LC.TrojanServer, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TROJAN"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.TROJAN,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	keys := make(map[[trojan.KeyLength]byte]string)
	for _, user := range config.Users {
		keys[trojan.Key(user.Password)] = user.Username
	}

	var pickCipher core.Cipher
	if config.TrojanSSOption.Enabled {
		if config.TrojanSSOption.Password == "" {
			return nil, errors.New("empty password")
		}
		if config.TrojanSSOption.Method == "" {
			config.TrojanSSOption.Method = "AES-128-GCM"
		}
		pickCipher, err = core.PickCipher(config.TrojanSSOption.Method, nil, config.TrojanSSOption.Password)
		if err != nil {
			return nil, err
		}
	}
	sl = &Listener{false, config, nil, keys, pickCipher, h}

	tlsConfig := &tls.Config{}
	var realityBuilder *reality.Builder
	var httpHandler http.Handler

	if config.Certificate != "" && config.PrivateKey != "" {
		cert, err := N.ParseCert(config.Certificate, config.PrivateKey, C.Path)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if config.RealityConfig.PrivateKey != "" {
		if tlsConfig.Certificates != nil {
			return nil, errors.New("certificate is unavailable in reality")
		}
		realityBuilder, err = config.RealityConfig.Build()
		if err != nil {
			return nil, err
		}
	}
	if config.WsPath != "" {
		httpMux := http.NewServeMux()
		httpMux.HandleFunc(config.WsPath, func(w http.ResponseWriter, r *http.Request) {
			conn, err := mihomoVMess.StreamUpgradedWebsocketConn(w, r)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			sl.HandleConn(conn, tunnel, additions...)
		})
		httpHandler = httpMux
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
	}
	if config.GrpcServiceName != "" {
		httpHandler = gun.NewServerHandler(gun.ServerOption{
			ServiceName: config.GrpcServiceName,
			ConnHandler: func(conn net.Conn) {
				sl.HandleConn(conn, tunnel, additions...)
			},
			HttpHandler: httpHandler,
		})
		tlsConfig.NextProtos = append([]string{"h2"}, tlsConfig.NextProtos...) // h2 must before http/1.1
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//TCP
		l, err := inbound.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if realityBuilder != nil {
			l = realityBuilder.NewListener(l)
		} else if len(tlsConfig.Certificates) > 0 {
			l = tls.NewListener(l, tlsConfig)
		} else if !config.TrojanSSOption.Enabled {
			return nil, errors.New("disallow using Trojan without both certificates/reality/ss config")
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			if httpHandler != nil {
				_ = http.Serve(l, httpHandler)
				return
			}
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}

				go sl.HandleConn(c, tunnel, additions...)
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
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	defer conn.Close()

	if l.pickCipher != nil {
		conn = l.pickCipher.StreamConn(conn)
	}

	var key [trojan.KeyLength]byte
	if _, err := io.ReadFull(conn, key[:]); err != nil {
		//log.Warnln("read key error: %s", err.Error())
		return
	}

	if user, ok := l.keys[key]; ok {
		additions = append(additions, inbound.WithInUser(user))
	} else {
		//log.Warnln("no such key")
		return
	}

	var crlf [2]byte
	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		//log.Warnln("read crlf error: %s", err.Error())
		return
	}

	l.handleConn(false, conn, tunnel, additions...)
}

func (l *Listener) handleConn(inMux bool, conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	if inMux {
		defer conn.Close()
	}

	command, err := socks5.ReadByte(conn)
	if err != nil {
		//log.Warnln("read command error: %s", err.Error())
		return
	}

	switch command {
	case trojan.CommandTCP, trojan.CommandUDP, trojan.CommandMux:
	default:
		//log.Warnln("unknown command: %d", command)
		return
	}

	target, err := socks5.ReadAddr0(conn)
	if err != nil {
		//log.Warnln("read target error: %s", err.Error())
		return
	}

	if !inMux {
		var crlf [2]byte
		if _, err := io.ReadFull(conn, crlf[:]); err != nil {
			//log.Warnln("read crlf error: %s", err.Error())
			return
		}
	}

	switch command {
	case trojan.CommandTCP:
		//tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.TROJAN, additions...))
		l.handler.HandleSocket(target, conn, additions...)
	case trojan.CommandUDP:
		pc := trojan.NewPacketConn(conn)
		for {
			data, put, remoteAddr, err := pc.WaitReadFrom()
			if err != nil {
				if put != nil {
					put()
				}
				break
			}
			cPacket := &packet{
				pc:      pc,
				rAddr:   remoteAddr,
				payload: data,
				put:     put,
			}

			tunnel.HandleUDPPacket(inbound.NewPacket(target, cPacket, C.TROJAN, additions...))
		}
	case trojan.CommandMux:
		if inMux {
			//log.Warnln("invalid command: %d", command)
			return
		}
		smuxConfig := smux.DefaultConfig()
		smuxConfig.KeepAliveDisabled = true
		session, err := smux.Server(conn, smuxConfig)
		if err != nil {
			//log.Warnln("smux server error: %s", err.Error())
			return
		}
		defer session.Close()
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go l.handleConn(true, stream, tunnel, additions...)
		}
	}
}
