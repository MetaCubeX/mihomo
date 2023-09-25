package sing_hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/adapter/outbound"
	CN "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/sockopt"
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	"github.com/metacubex/sing-quic/hysteria2"

	E "github.com/sagernet/sing/common/exceptions"
)

type Listener struct {
	closed       bool
	config       LC.Hysteria2Server
	udpListeners []net.PacketConn
	services     []*hysteria2.Service[string]
}

func New(config LC.Hysteria2Server, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter, additions ...inbound.Addition) (*Listener, error) {
	var sl *Listener
	var err error
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HYSTERIA2"),
			inbound.WithSpecialRules(""),
		}
	}

	h := &sing.ListenerHandler{
		TcpIn:     tcpIn,
		UdpIn:     udpIn,
		Type:      C.HYSTERIA2,
		Additions: additions,
	}

	sl = &Listener{false, config, nil, nil}

	cert, err := CN.ParseCert(config.Certificate, config.PrivateKey)
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

	var salamanderPassword string
	if len(config.Obfs) > 0 {
		if config.ObfsPassword == "" {
			return nil, errors.New("missing obfs password")
		}
		switch config.Obfs {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = config.ObfsPassword
		default:
			return nil, fmt.Errorf("unknown obfs type: %s", config.Obfs)
		}
	}
	var masqueradeHandler http.Handler
	if config.Masquerade != "" {
		masqueradeURL, err := url.Parse(config.Masquerade)
		if err != nil {
			return nil, E.Cause(err, "parse masquerade URL")
		}
		switch masqueradeURL.Scheme {
		case "file":
			masqueradeHandler = http.FileServer(http.Dir(masqueradeURL.Path))
		case "http", "https":
			masqueradeHandler = &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(masqueradeURL)
					r.Out.Host = r.In.Host
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusBadGateway)
				},
			}
		default:
			return nil, E.New("unknown masquerade URL scheme: ", masqueradeURL.Scheme)
		}
	}

	service, err := hysteria2.NewService[string](hysteria2.ServiceOptions{
		Context:               context.Background(),
		Logger:                log.SingLogger,
		SendBPS:               outbound.StringToBps(config.Up),
		ReceiveBPS:            outbound.StringToBps(config.Down),
		SalamanderPassword:    salamanderPassword,
		TLSConfig:             tlsConfig,
		IgnoreClientBandwidth: config.IgnoreClientBandwidth,
		Handler:               h,
		MasqueradeHandler:     masqueradeHandler,
		CWND:                  config.CWND,
	})
	if err != nil {
		return nil, err
	}

	userNameList := make([]string, 0, len(config.Users))
	userPasswordList := make([]string, 0, len(config.Users))
	for name, password := range config.Users {
		userNameList = append(userNameList, name)
		userPasswordList = append(userPasswordList, password)
	}
	service.UpdateUsers(userNameList, userPasswordList)

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr
		_service := *service
		service := &_service // make a copy

		ul, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, err
		}

		err = sockopt.UDPReuseaddr(ul.(*net.UDPConn))
		if err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		sl.udpListeners = append(sl.udpListeners, ul)
		sl.services = append(sl.services, service)

		go func() {
			_ = service.Start(ul)
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, service := range l.services {
		err := service.Close()
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
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}
