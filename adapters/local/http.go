package adapters

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
)

type PeekedConn struct {
	net.Conn
	Peeked []byte
}

func (c *PeekedConn) Read(p []byte) (n int, err error) {
	if len(c.Peeked) > 0 {
		n = copy(p, c.Peeked)
		c.Peeked = c.Peeked[n:]
		if len(c.Peeked) == 0 {
			c.Peeked = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

type HttpAdapter struct {
	addr *C.Addr
	conn *PeekedConn
}

func (h *HttpAdapter) Close() {
	h.conn.Close()
}

func (h *HttpAdapter) Addr() *C.Addr {
	return h.addr
}

func (h *HttpAdapter) Conn() net.Conn {
	return h.conn
}

func NewHttp(host string, peeked []byte, conn net.Conn) *HttpAdapter {
	return &HttpAdapter{
		addr: parseHttpAddr(host),
		conn: &PeekedConn{
			Peeked: peeked,
			Conn:   conn,
		},
	}
}
