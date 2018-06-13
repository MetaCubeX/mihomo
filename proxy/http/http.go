package http

import (
	"io"
	"net"
	"net/http"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

type HttpAdapter struct {
	addr *C.Addr
	r    *http.Request
	w    http.ResponseWriter
	done chan struct{}
}

func (h *HttpAdapter) Close() {
	h.done <- struct{}{}
}

func (h *HttpAdapter) Addr() *C.Addr {
	return h.addr
}

func (h *HttpAdapter) Connect(proxy C.ProxyAdapter) {
	req := http.Transport{
		Dial: func(string, string) (net.Conn, error) {
			return proxy.Conn(), nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	resp, err := req.RoundTrip(h.r)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	header := h.w.Header()
	for k, vv := range resp.Header {
		for _, v := range vv {
			header.Add(k, v)
		}
	}
	h.w.WriteHeader(resp.StatusCode)
	io.Copy(h.w, resp.Body)
}

func NewHttp(host string, w http.ResponseWriter, r *http.Request) (*HttpAdapter, chan struct{}) {
	done := make(chan struct{})
	return &HttpAdapter{
		addr: parseHttpAddr(host),
		r:    r,
		w:    w,
		done: done,
	}, done
}
