package tuic

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"golang.org/x/exp/slices"
)

const ServerMaxIncomingStreams = (1 << 32) - 1

type Listener struct {
	closed       bool
	config       LC.TuicServer
	udpListeners []net.PacketConn
	servers      []*tuic.Server
}

func New(config LC.TuicServer, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TUIC"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.TUIC,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	cert, err := CN.ParseCert(config.Certificate, config.PrivateKey, C.Path)
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
		MaxIncomingStreams:    ServerMaxIncomingStreams,
		MaxIncomingUniStreams: ServerMaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             true,
	}
	quicConfig.InitialStreamReceiveWindow = tuic.DefaultStreamReceiveWindow / 10
	quicConfig.MaxStreamReceiveWindow = tuic.DefaultStreamReceiveWindow
	quicConfig.InitialConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow / 10
	quicConfig.MaxConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow

	packetOverHead := tuic.PacketOverHeadV4
	if len(config.Token) == 0 {
		packetOverHead = tuic.PacketOverHeadV5
	}

	if config.CWND == 0 {
		config.CWND = 32
	}

	if config.MaxUdpRelayPacketSize == 0 {
		config.MaxUdpRelayPacketSize = 1500
	}
	maxDatagramFrameSize := config.MaxUdpRelayPacketSize + packetOverHead
	if maxDatagramFrameSize > 1400 {
		maxDatagramFrameSize = 1400
	}
	config.MaxUdpRelayPacketSize = maxDatagramFrameSize - packetOverHead
	quicConfig.MaxDatagramFrameSize = int64(maxDatagramFrameSize)

	handleTcpFn := func(conn net.Conn, addr socks5.Addr, _additions ...inbound.Addition) error {
		newAdditions := additions
		if len(_additions) > 0 {
			newAdditions = slices.Clone(additions)
			newAdditions = append(newAdditions, _additions...)
		}
		conn, metadata := inbound.NewSocket(addr, conn, C.TUIC, newAdditions...)
		if h.IsSpecialFqdn(metadata.Host) {
			go func() { // ParseSpecialFqdn will block, so open a new goroutine
				_ = h.ParseSpecialFqdn(
					sing.WithAdditions(context.Background(), newAdditions...),
					conn,
					sing.ConvertMetadata(metadata),
				)
			}()
			return nil
		}
		go tunnel.HandleTCPConn(conn, metadata)
		return nil
	}
	handleUdpFn := func(addr socks5.Addr, packet C.UDPPacket, _additions ...inbound.Addition) error {
		newAdditions := additions
		if len(_additions) > 0 {
			newAdditions = slices.Clone(additions)
			newAdditions = append(newAdditions, _additions...)
		}
		tunnel.HandleUDPPacket(inbound.NewPacket(addr, packet, C.TUIC, newAdditions...))
		return nil
	}

	option := &tuic.ServerOption{
		HandleTcpFn:           handleTcpFn,
		HandleUdpFn:           handleUdpFn,
		TlsConfig:             tlsConfig,
		QuicConfig:            quicConfig,
		CongestionController:  config.CongestionController,
		AuthenticationTimeout: time.Duration(config.AuthenticationTimeout) * time.Millisecond,
		MaxUdpRelayPacketSize: config.MaxUdpRelayPacketSize,
		CWND:                  config.CWND,
	}
	if len(config.Token) > 0 {
		tokens := make([][32]byte, len(config.Token))
		for i, token := range config.Token {
			tokens[i] = tuic.GenTKN(token)
		}
		option.Tokens = tokens
	}
	if len(config.Users) > 0 {
		users := make(map[[16]byte]string)
		for _uuid, password := range config.Users {
			users[uuid.FromStringOrNil(_uuid)] = password
		}
		option.Users = users
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

		var server *tuic.Server
		server, err = tuic.NewServer(option, ul)
		if err != nil {
			return nil, err
		}

		sl.servers = append(sl.servers, server)

		go func() {
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

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, lis := range l.servers {
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

func (l *Listener) Config() LC.TuicServer {
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}
