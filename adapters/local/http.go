package adapters

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

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

func NewHttp(host string, peeked []byte, isHTTP bool, conn net.Conn) *HttpAdapter {
	return &HttpAdapter{
		addr: parseHttpAddr(host),
		conn: &PeekedConn{
			Peeked: peeked,
			Conn:   conn,
			host:   host,
			isHTTP: isHTTP,
		},
	}
}

// ParserHTTPHostHeader returns the HTTP Host header from br without
// consuming any of its bytes. It returns "" if it can't find one.
func ParserHTTPHostHeader(br *bufio.Reader) (method, host string) {
	// br := bufio.NewReader(bytes.NewReader(data))
	const maxPeek = 4 << 10
	peekSize := 0
	for {
		peekSize++
		if peekSize > maxPeek {
			b, _ := br.Peek(br.Buffered())
			return method, httpHostHeaderFromBytes(b)
		}
		b, err := br.Peek(peekSize)
		if n := br.Buffered(); n > peekSize {
			b, _ = br.Peek(n)
			peekSize = n
		}
		if len(b) > 0 {
			if b[0] < 'A' || b[0] > 'Z' {
				// Doesn't look like an HTTP verb
				// (GET, POST, etc).
				return
			}
			if bytes.Index(b, crlfcrlf) != -1 || bytes.Index(b, lflf) != -1 {
				req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
				if err != nil {
					return
				}
				if len(req.Header["Host"]) > 1 {
					// TODO(bradfitz): what does
					// ReadRequest do if there are
					// multiple Host headers?
					return
				}
				return req.Method, req.Host
			}
		}
		if err != nil {
			return method, httpHostHeaderFromBytes(b)
		}
	}
}

var (
	lfHostColon = []byte("\nHost:")
	lfhostColon = []byte("\nhost:")
	crlf        = []byte("\r\n")
	lf          = []byte("\n")
	crlfcrlf    = []byte("\r\n\r\n")
	lflf        = []byte("\n\n")
)

func httpHostHeaderFromBytes(b []byte) string {
	if i := bytes.Index(b, lfHostColon); i != -1 {
		return string(bytes.TrimSpace(untilEOL(b[i+len(lfHostColon):])))
	}
	if i := bytes.Index(b, lfhostColon); i != -1 {
		return string(bytes.TrimSpace(untilEOL(b[i+len(lfhostColon):])))
	}
	return ""
}

// untilEOL returns v, truncated before the first '\n' byte, if any.
// The returned slice may include a '\r' at the end.
func untilEOL(v []byte) []byte {
	if i := bytes.IndexByte(v, '\n'); i != -1 {
		return v[:i]
	}
	return v
}
