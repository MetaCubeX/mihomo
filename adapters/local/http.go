package adapters

import (
	"net/http"

	C "github.com/Dreamacro/clash/constant"
)

type HttpAdapter struct {
	addr *C.Addr
	R    *http.Request
	W    http.ResponseWriter
	done chan struct{}
}

func (h *HttpAdapter) Close() {
	h.done <- struct{}{}
}

func (h *HttpAdapter) Addr() *C.Addr {
	return h.addr
}

func NewHttp(host string, w http.ResponseWriter, r *http.Request) (*HttpAdapter, chan struct{}) {
	done := make(chan struct{})
	return &HttpAdapter{
		addr: parseHttpAddr(host),
		R:    r,
		W:    w,
		done: done,
	}, done
}
