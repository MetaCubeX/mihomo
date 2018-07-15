package http

import (
	"context"
	"net"
	"net/http"
	"strings"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"

	"github.com/riobard/go-shadowsocks2/socks"
	log "github.com/sirupsen/logrus"
)

var (
	tun = tunnel.GetInstance()
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
	req, done := NewHttp(addr, w, r)
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
	tun.Add(NewHttps(r.Host, conn))
}

func parseHttpAddr(target string) *C.Addr {
	host, port, _ := net.SplitHostPort(target)
	ipAddr, err := net.ResolveIPAddr("ip", host)
	var resolveIP *net.IP
	if err == nil {
		resolveIP = &ipAddr.IP
	}

	var addType int
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		addType = socks.AtypDomainName
	case ip.To4() == nil:
		addType = socks.AtypIPv6
	default:
		addType = socks.AtypIPv4
	}

	return &C.Addr{
		NetWork:  C.TCP,
		AddrType: addType,
		Host:     host,
		IP:       resolveIP,
		Port:     port,
	}
}
