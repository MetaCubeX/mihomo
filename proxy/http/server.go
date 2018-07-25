package http

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/Dreamacro/clash/adapters/local"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"

	log "github.com/sirupsen/logrus"
)

var (
	tun = tunnel.Instance()
)

func NewHttpProxy(addr string) (*C.ProxySignal, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	closed := make(chan struct{})
	signal := &C.ProxySignal{
		Done:   done,
		Closed: closed,
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	go func() {
		log.Infof("HTTP proxy listening at: %s", addr)
		server.Serve(l)
	}()

	go func() {
		<-done
		server.Shutdown(context.Background())
		l.Close()
		closed <- struct{}{}
	}()

	return signal, nil
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	addr := r.Host
	// padding default port
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	req, done := adapters.NewHttp(addr, w, r)
	tun.Add(req)
	<-done
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	// w.WriteHeader(http.StatusOK) doesn't works in Safari
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	tun.Add(adapters.NewHttps(r.Host, conn))
}
