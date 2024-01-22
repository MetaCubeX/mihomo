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

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-quic/hysteria2"

	E "github.com/sagernet/sing/common/exceptions"
)

type Listener struct {
	closed       bool
	config       LC.Hysteria2Server
	udpListeners []net.PacketConn
	services     []*hysteria2.Service[string]
}

func New(config LC.Hysteria2Server, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	var sl *Listener
	var err error
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HYSTERIA2"),
			inbound.WithSpecialRules(""),
		}
	}

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.HYSTERIA2,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	sl = &Listener{false, config, nil, nil}

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

	if config.UdpMTU == 0 {
		// "1200" from quic-go's MaxDatagramSize
		// "-3" from quic-go's DatagramFrame.MaxDataLen
		config.UdpMTU = 1200 - 3
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
		UdpMTU:                config.UdpMTU,
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
