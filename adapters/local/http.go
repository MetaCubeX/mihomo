package adapters

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

// PeekedConn handle http connection and buffed HTTP data
type PeekedConn struct {
	net.Conn
	Peeked []byte
	host   string
	isHTTP bool
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

	// Sometimes firefox just open a socket to process multiple domains in HTTP
	// The temporary solution is to return io.EOF when encountering different HOST
	if c.isHTTP {
		br := bufio.NewReader(bytes.NewReader(p))
		_, hostName := ParserHTTPHostHeader(br)
		if hostName != "" {
			if !strings.Contains(hostName, ":") {
				hostName += ":80"
			}

			if hostName != c.host {
				return 0, io.EOF
			}
		}
	}

	return c.Conn.Read(p)
}

// HTTPAdapter is a adapter for HTTP connection
type HTTPAdapter struct {
	addr *C.Addr
	conn *PeekedConn
}

// Close HTTP connection
func (h *HTTPAdapter) Close() {
	h.conn.Close()
}

// Addr return destination address
func (h *HTTPAdapter) Addr() *C.Addr {
	return h.addr
}

// Conn return raw net.Conn of HTTP
func (h *HTTPAdapter) Conn() net.Conn {
	return h.conn
}

// NewHTTP is HTTPAdapter generator
func NewHTTP(host string, peeked []byte, isHTTP bool, conn net.Conn) *HTTPAdapter {
	return &HTTPAdapter{
		addr: parseHTTPAddr(host),
		conn: &PeekedConn{
			Peeked: peeked,
			Conn:   conn,
			host:   host,
			isHTTP: isHTTP,
		},
	}
}
