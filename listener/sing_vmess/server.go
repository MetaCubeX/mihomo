package sing_vmess

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/metadata"
)

type Listener struct {
	closed    bool
	config    string
	listeners []net.Listener
	service   *vmess.Service[string]
}

var _listener *Listener

func New(config string, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) (*Listener, error) {
	addr, username, password, err := parseVmessURL(config)
	if err != nil {
		return nil, err
	}

	h := &sing.ListenerHandler{
		TcpIn: tcpIn,
		UdpIn: udpIn,
		Type:  C.VMESS,
	}

	service := vmess.NewService[string](h)
	err = service.UpdateUsers([]string{username}, []string{password}, []int{1})
	if err != nil {
		return nil, err
	}

	err = service.Start()
	if err != nil {
		return nil, err
	}

	sl := &Listener{false, config, nil, service}
	_listener = sl

	for _, addr := range strings.Split(addr, ",") {
		addr := addr

		//TCP
		l, err := inbound.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			log.Infoln("Vmess proxy listening at: %s", l.Addr().String())
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)

				go sl.HandleConn(c, tcpIn)
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
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, in chan<- C.ConnContext) {
	err := l.service.NewConnection(context.TODO(), conn, metadata.Metadata{
		Protocol: "vmess",
		Source:   metadata.ParseSocksaddr(conn.RemoteAddr().String()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleVmess(conn net.Conn, in chan<- C.ConnContext) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn, in)
		return true
	}
	return false
}

func parseVmessURL(s string) (addr, username, password string, err error) {
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
