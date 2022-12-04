package tuic

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/metacubex/quic-go"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/sockopt"
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/Dreamacro/clash/transport/tuic"
)

type Listener struct {
	closed       bool
	config       LC.TuicServer
	udpListeners []net.PacketConn
	servers      []*tuic.Server
}

func New(config LC.TuicServer, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) (*Listener, error) {
	cert, err := tls.LoadX509KeyPair(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if len(config.ALPN) > 0 {
		tlsConfig.NextProtos = config.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:        time.Duration(config.MaxIdleTime) * time.Millisecond,
		MaxIncomingStreams:    1 >> 32,
		MaxIncomingUniStreams: 1 >> 32,
		EnableDatagrams:       true,
	}
	quicConfig.InitialStreamReceiveWindow = tuic.DefaultStreamReceiveWindow / 10
	quicConfig.MaxStreamReceiveWindow = tuic.DefaultStreamReceiveWindow
	quicConfig.InitialConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow / 10
	quicConfig.MaxConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow

	tokens := make([][32]byte, len(config.Token))
	for i, token := range config.Token {
		tokens[i] = tuic.GenTKN(token)
	}

	option := &tuic.ServerOption{
		HandleTcpFn: func(conn net.Conn, addr socks5.Addr) error {
			tcpIn <- inbound.NewSocket(addr, conn, C.TUIC)
			return nil
		},
		HandleUdpFn: func(addr socks5.Addr, packet C.UDPPacket) error {
			select {
			case udpIn <- inbound.NewPacket(addr, packet, C.TUIC):
			default:
			}
			return nil
		},
		TlsConfig:             tlsConfig,
		QuicConfig:            quicConfig,
		Tokens:                tokens,
		CongestionController:  config.CongestionController,
		AuthenticationTimeout: time.Duration(config.AuthenticationTimeout) * time.Millisecond,
		MaxUdpRelayPacketSize: config.MaxUdpRelayPacketSize,
	}

	sl := &Listener{false, config, nil, nil}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		ul, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, err
		}

		err = sockopt.UDPReuseaddr(ul.(*net.UDPConn))
		if err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		sl.udpListeners = append(sl.udpListeners, ul)

		server, err := tuic.NewServer(option, ul)
		if err != nil {
			return nil, err
		}

		sl.servers = append(sl.servers, server)

		go func() {
			log.Infoln("Tuic proxy listening at: %s", ul.LocalAddr().String())
			err := server.Serve()
			if err != nil {
				if sl.closed {
					return
				}
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() {
	l.closed = true
	for _, lis := range l.servers {
		_ = lis.Close()
	}
	for _, lis := range l.udpListeners {
		_ = lis.Close()
	}
}

func (l *Listener) Config() LC.TuicServer {
	return l.config
}
