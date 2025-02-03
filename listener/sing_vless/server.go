package sing_vless

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/sing-vmess/vless"
	utls "github.com/metacubex/utls"
	"github.com/sagernet/reality"
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
	var realityConfig *reality.Config
	var httpMux *http.ServeMux

	if config.Certificate != "" && config.PrivateKey != "" {
		cert, err := N.ParseCert(config.Certificate, config.PrivateKey, C.Path)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
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
	if config.RealityConfig.PrivateKey != "" {
		if tlsConfig.Certificates != nil {
			return nil, errors.New("certificate is unavailable in reality")
		}
		realityConfig = &reality.Config{}
		realityConfig.SessionTicketsDisabled = true
		realityConfig.Type = "tcp"
		realityConfig.Dest = config.RealityConfig.Dest
		realityConfig.Time = ntp.Now
		realityConfig.ServerNames = make(map[string]bool)
		for _, it := range config.RealityConfig.ServerNames {
			realityConfig.ServerNames[it] = true
		}
		privateKey, err := base64.RawURLEncoding.DecodeString(config.RealityConfig.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decode private key: %w", err)
		}
		if len(privateKey) != 32 {
			return nil, errors.New("invalid private key")
		}
		realityConfig.PrivateKey = privateKey

		realityConfig.MaxTimeDiff = time.Duration(config.RealityConfig.MaxTimeDifference) * time.Microsecond

		realityConfig.ShortIds = make(map[[8]byte]bool)
		for i, shortIDString := range config.RealityConfig.ShortID {
			var shortID [8]byte
			decodedLen, err := hex.Decode(shortID[:], []byte(shortIDString))
			if err != nil {
				return nil, fmt.Errorf("decode short_id[%d] '%s': %w", i, shortIDString, err)
			}
			if decodedLen > 8 {
				return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
			}
			realityConfig.ShortIds[shortID] = true
		}

		realityConfig.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return inner.HandleTcp(address, config.RealityConfig.Proxy)
		}
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//TCP
		l, err := inbound.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if realityConfig != nil {
			l = reality.NewListener(l, realityConfig)
			// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
			// We fixed it by calling Close() directly.
			l = realityListenerWrapper{l}
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

type realityConnWrapper struct {
	*reality.Conn
}

func (c realityConnWrapper) Upstream() any {
	return c.Conn
}

func (c realityConnWrapper) CloseWrite() error {
	return c.Close()
}

type realityListenerWrapper struct {
	net.Listener
}

func (l realityListenerWrapper) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return realityConnWrapper{c.(*reality.Conn)}, nil
}
