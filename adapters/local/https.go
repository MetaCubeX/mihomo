package adapters

import (
	"bufio"
	"net"

	C "github.com/Dreamacro/clash/constant"
)

type HttpsAdapter struct {
	addr *C.Addr
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (h *HttpsAdapter) Close() {
	h.conn.Close()
}

func (h *HttpsAdapter) Addr() *C.Addr {
	return h.addr
}

func (h *HttpsAdapter) Conn() net.Conn {
	return h.conn
}

func NewHttps(host string, conn net.Conn) *HttpsAdapter {
	return &HttpsAdapter{
		addr: parseHttpAddr(host),
		conn: conn,
	}
}
