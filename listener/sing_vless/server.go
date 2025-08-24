package sing_vless

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strings"
	"unsafe"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/sing-vmess/vless"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

func init() {
	vless.RegisterTLS(func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := network.CastReader[*reality.Conn](conn) // *utls.Conn
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn)
	})

	vless.RegisterTLS(func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := network.CastReader[*tlsC.UConn](conn) // *utls.UConn
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn.Conn).Elem(), unsafe.Pointer(tlsConn.Conn)
	})

	vless.RegisterTLS(func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := network.CastReader[*encryption.CommonConn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.Conn, reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn)
	})
}

type Listener struct {
	closed     bool
	config     LC.VlessServer
	listeners  []net.Listener
	service    *vless.Service[string]
	decryption *encryption.ServerInstance
}

func New(config LC.VlessServer, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-VLESS"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.VLESS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	service := vless.NewService[string](log.SingLogger, h)
	service.UpdateUsers(
		common.Map(config.Users, func(it LC.VlessUser) string {
			return it.Username
		}),
		common.Map(config.Users, func(it LC.VlessUser) string {
			return it.UUID
		}),
		common.Map(config.Users, func(it LC.VlessUser) string {
			return it.Flow
		}))

	sl = &Listener{config: config, service: service}

	sl.decryption, err = encryption.NewServer(config.Decryption)
	if err != nil {
		return nil, err
	}
	if sl.decryption != nil {
		defer func() { // decryption must be closed to avoid the goroutine leak
			if err != nil {
				_ = sl.decryption.Close()
				sl.decryption = nil
			}
		}()
	}

	tlsConfig := &tlsC.Config{}
	var realityBuilder *reality.Builder
	var httpServer http.Server

	if config.Certificate != "" && config.PrivateKey != "" {
		cert, err := ca.LoadTLSKeyPair(config.Certificate, config.PrivateKey, C.Path)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tlsC.Certificate{tlsC.UCertificate(cert)}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig, C.Path)
			if err != nil {
				return nil, err
			}
		}
	}
	if config.RealityConfig.PrivateKey != "" {
		if tlsConfig.Certificates != nil {
			return nil, errors.New("certificate is unavailable in reality")
		}
		realityBuilder, err = config.RealityConfig.Build(tunnel)
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
		httpServer.Handler = httpMux
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
	}
	if config.GrpcServiceName != "" {
		httpServer.Handler = gun.NewServerHandler(gun.ServerOption{
			ServiceName: config.GrpcServiceName,
			ConnHandler: func(conn net.Conn) {
				sl.HandleConn(conn, tunnel, additions...)
			},
			HttpHandler: httpServer.Handler,
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
			if httpServer.Handler != nil {
				l = tlsC.NewListenerForHttps(l, &httpServer, tlsConfig)
			} else {
				l = tlsC.NewListener(l, tlsConfig)
			}
		} else if sl.decryption == nil {
			return nil, errors.New("disallow using Vless without any certificates/reality/decryption config")
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			if httpServer.Handler != nil {
				_ = httpServer.Serve(l)
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
	if l.decryption != nil {
		_ = l.decryption.Close()
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
	ctx := sing.WithAdditions(context.TODO(), additions...)
	if l.decryption != nil {
		var err error
		conn, err = l.decryption.Handshake(conn)
		if err != nil {
			return
		}
	}
	err := l.service.NewConnection(ctx, conn, metadata.Metadata{
		Protocol: "vless",
		Source:   metadata.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}
