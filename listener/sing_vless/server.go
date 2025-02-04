package sing_vless

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strings"
	"unsafe"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/sing-vmess/vless"
	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/metadata"
)

func init() {
	vless.RegisterTLS(func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := common.Cast[*reality.Conn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn)
	})

	vless.RegisterTLS(func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := common.Cast[*utls.UConn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn.Conn).Elem(), unsafe.Pointer(tlsConn.Conn)
	})

	vless.RegisterTLS(func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := common.Cast[*tlsC.UConn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn.Conn).Elem(), unsafe.Pointer(tlsConn.Conn)
	})
}

type Listener struct {
	closed    bool
	config    LC.VlessServer
	listeners []net.Listener
	service   *vless.Service[string]
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

	sl = &Listener{false, config, nil, service}

	tlsConfig := &tls.Config{}
	var realityBuilder *reality.Builder
	var httpMux *http.ServeMux

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
		httpMux = http.NewServeMux()
		httpMux.HandleFunc(config.WsPath, func(w http.ResponseWriter, r *http.Request) {
			conn, err := mihomoVMess.StreamUpgradedWebsocketConn(w, r)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			sl.HandleConn(conn, tunnel)
		})
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
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
		} else {
			return nil, errors.New("disallow using Vless without both certificates/reality config")
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			if httpMux != nil {
				_ = http.Serve(l, httpMux)
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
	err := l.service.NewConnection(ctx, conn, metadata.Metadata{
		Protocol: "vless",
		Source:   metadata.ParseSocksaddr(conn.RemoteAddr().String()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}
