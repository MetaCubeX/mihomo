package http

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/auth"
	C "github.com/Dreamacro/clash/constant"
	authStore "github.com/Dreamacro/clash/listener/auth"
	"github.com/Dreamacro/clash/log"
)

type Listener struct {
	listener net.Listener
	address  string
	closed   bool
	cache    *cache.Cache
}

func New(addr string, in chan<- C.ConnContext) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	hl := &Listener{l, addr, false, cache.New(30 * time.Second)}
	go func() {
		for {
			c, err := hl.listener.Accept()
			if err != nil {
				if hl.closed {
					break
				}
				continue
			}
			go HandleConn(c, in, hl.cache)
		}
	}()

	return hl, nil
}

func (l *Listener) Close() {
	l.closed = true
	l.listener.Close()
}

func (l *Listener) Address() string {
	return l.address
}

func canActivate(loginStr string, authenticator auth.Authenticator, cache *cache.Cache) (ret bool) {
	if result := cache.Get(loginStr); result != nil {
		ret = result.(bool)
		return
	}
	loginData, err := base64.StdEncoding.DecodeString(loginStr)
	login := strings.Split(string(loginData), ":")
	ret = err == nil && len(login) == 2 && authenticator.Verify(login[0], login[1])

	cache.Put(loginStr, ret, time.Minute)
	return
}

func HandleConn(conn net.Conn, in chan<- C.ConnContext, cache *cache.Cache) {
	br := bufio.NewReader(conn)

keepAlive:
	request, err := http.ReadRequest(br)
	if err != nil || request.URL.Host == "" {
		conn.Close()
		return
	}

	keepAlive := strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"
	authenticator := authStore.Authenticator()
	if authenticator != nil {
		if authStrings := strings.Split(request.Header.Get("Proxy-Authorization"), " "); len(authStrings) != 2 {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			if keepAlive {
				goto keepAlive
			}
			return
		} else if !canActivate(authStrings[1], authenticator, cache) {
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			log.Infoln("Auth failed from %s", conn.RemoteAddr().String())
			if keepAlive {
				goto keepAlive
			}
			conn.Close()
			return
		}
	}

	if request.Method == http.MethodConnect {
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			conn.Close()
			return
		}
		in <- inbound.NewHTTPS(request, conn)
		return
	}

	in <- inbound.NewHTTP(request, conn)
}
