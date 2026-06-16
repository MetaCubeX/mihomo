package hysteria2_realm

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed    bool
	config    LC.Hysteria2RealmServer
	listeners []net.Listener
	server    *server
	cancel    func()
}

const (
	DefaultMaxRealms        = 65536
	DefaultMaxRealmsPerIP   = 4
	DefaultRealmNamePattern = defaultRealmNamePattern
)

func DefaultALPN() []string { return []string{"h2", "http/1.1"} }

func New(config LC.Hysteria2RealmServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HYSTERIA2-REALM"),
			inbound.WithSpecialRules(""),
		}
	}

	pat, err := regexp.Compile(config.RealmNamePattern)
	if err != nil {
		return nil, fmt.Errorf("invalid realm name pattern %q: %v", config.RealmNamePattern, err)
	}
	s := newServer(serverConfig{
		realmToken:     config.Token,
		maxRealms:      config.MaxRealms,
		maxRealmsPerIP: config.MaxRealmsPerIP,
		proxyHeader:    config.TrustedProxyHeader,
		realmIDPattern: pat,
	})

	tlsConfig := &tls.Config{Time: ntp.Now}
	if config.Certificate != "" && config.PrivateKey != "" {
		certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig)
			if err != nil {
				return nil, err
			}
		}
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}

	sl := &Listener{config: config, server: s}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//TCP
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		if tlsConfig.GetCertificate != nil {
			l = tls.NewListener(l, tlsConfig)
		}
		sl.listeners = append(sl.listeners, l)

		srv := &http.Server{
			Handler:           s.routes(),
			ReadHeaderTimeout: 10 * time.Second,
		}

		go srv.Serve(l)
	}
	ctx, cancel := context.WithCancel(context.Background())
	sl.cancel = cancel
	go s.reaper(ctx)

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
	if l.cancel != nil {
		l.cancel()
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

func debugf(format string, v ...any) {
	log.Debugln("[RealmServer] "+format, v...)
}
