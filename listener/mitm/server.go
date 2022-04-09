package mitm

import (
	"crypto/tls"
	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/common/cert"
	C "github.com/Dreamacro/clash/constant"
	"net"
	"net/http"
)

type Handler interface {
	HandleRequest(*Session) (*http.Request, *http.Response) // Session.Response maybe nil
	HandleResponse(*Session) *http.Response
	HandleApiRequest(*Session) bool
	HandleError(*Session, error) // Session maybe nil
}

type Option struct {
	Addr    string
	ApiHost string

	TLSConfig  *tls.Config
	CertConfig *cert.Config

	Handler Handler
}

type Listener struct {
	*Option

	listener net.Listener
	addr     string
	closed   bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

// New the MITM proxy actually is a type of HTTP proxy
func New(option *Option, in chan<- C.ConnContext) (*Listener, error) {
	return NewWithAuthenticate(option, in, true)
}

func NewWithAuthenticate(option *Option, in chan<- C.ConnContext, authenticate bool) (*Listener, error) {
	l, err := net.Listen("tcp", option.Addr)
	if err != nil {
		return nil, err
	}

	var c *cache.LruCache[string, bool]
	if authenticate {
		c = cache.New[string, bool](cache.WithAge[string, bool](90))
	}

	hl := &Listener{
		listener: l,
		addr:     option.Addr,
		Option:   option,
	}
	go func() {
		for {
			conn, err1 := hl.listener.Accept()
			if err1 != nil {
				if hl.closed {
					break
				}
				continue
			}
			go HandleConn(conn, option, in, c)
		}
	}()

	return hl, nil
}
