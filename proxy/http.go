package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/Dreamacro/clash/constant"

	"github.com/riobard/go-shadowsocks2/socks"
	log "github.com/sirupsen/logrus"
)

func NewHttpProxy(port string) {
	server := &http.Server{
		Addr: fmt.Sprintf(":%s", port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}
	log.Infof("HTTP proxy :%s", port)
	server.ListenAndServe()
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	buf, _ := httputil.DumpRequestOut(r, true)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	addr := r.Host
	// padding default port
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	tun.Add(NewHttp(addr, conn, rw, buf))
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	// w.WriteHeader(http.StatusOK) doesn't works in Safari
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	tun.Add(NewHttp(r.Host, conn, rw, []byte{}))
}

type HttpAdapter struct {
	addr *constant.Addr
	conn net.Conn
	r    io.Reader
}

func (h *HttpAdapter) Writer() io.Writer {
	return h.conn
}

func (h *HttpAdapter) Reader() io.Reader {
	return h.r
}

func (h *HttpAdapter) Close() {
	h.conn.Close()
}

func (h *HttpAdapter) Addr() *constant.Addr {
	return h.addr
}

func parseHttpAddr(target string) *constant.Addr {
	host, port, _ := net.SplitHostPort(target)
	ipAddr, _ := net.ResolveIPAddr("ip", host)
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

	return &constant.Addr{
		AddrType: addType,
		Host:     host,
		IP:       &ipAddr.IP,
		Port:     port,
	}
}

func NewHttp(host string, conn net.Conn, rw *bufio.ReadWriter, payload []byte) *HttpAdapter {
	r := io.MultiReader(bytes.NewReader(payload), rw)
	return &HttpAdapter{
		conn: conn,
		addr: parseHttpAddr(host),
		r:    r,
	}
}
