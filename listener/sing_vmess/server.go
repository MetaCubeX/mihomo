package sing_vmess

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/ntp"
	clashVMess "github.com/Dreamacro/clash/transport/vmess"

	vmess "github.com/metacubex/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/metadata"
)

type Listener struct {
	closed    bool
	config    LC.VmessServer
	listeners []net.Listener
	service   *vmess.Service[string]
}

var _listener *Listener

func New(config LC.VmessServer, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-VMESS"),
			inbound.WithSpecialRules(""),
		}
		defer func() {
			_listener = sl
		}()
	}
	h := &sing.ListenerHandler{
		Tunnel:    tunnel,
		Type:      C.VMESS,
		Additions: additions,
	}

	service := vmess.NewService[string](h, vmess.ServiceWithDisableHeaderProtection(), vmess.ServiceWithTimeFunc(ntp.Now))
	err = service.UpdateUsers(
		common.Map(config.Users, func(it LC.VmessUser) string {
			return it.Username
		}),
		common.Map(config.Users, func(it LC.VmessUser) string {
			return it.UUID
		}),
		common.Map(config.Users, func(it LC.VmessUser) int {
			return it.AlterID
		}))
	if err != nil {
		return nil, err
	}

	err = service.Start()
	if err != nil {
		return nil, err
	}

	sl = &Listener{false, config, nil, service}

	tlsConfig := &tls.Config{}
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
			conn, err := clashVMess.StreamUpgradedWebsocketConn(w, r)
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
		if len(tlsConfig.Certificates) > 0 {
			l = tls.NewListener(l, tlsConfig)
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
				N.TCPKeepAlive(c)

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
	err := l.service.Close()
	if err != nil {
		retErr = err
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
		Protocol: "vmess",
		Source:   metadata.ParseSocksaddr(conn.RemoteAddr().String()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleVmess(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return false
}

func ParseVmessURL(s string) (addr, username, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
