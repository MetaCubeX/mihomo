package obfs

import (
	"bytes"
	"encoding/hex"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/convert"
	"github.com/Dreamacro/clash/common/pool"
)

func init() {
	register("http_simple", newHTTPSimple, 0)
}

type httpObfs struct {
	*Base
	post bool
}

func newHTTPSimple(b *Base) Obfs {
	return &httpObfs{Base: b}
}

type httpConn struct {
	net.Conn
	*httpObfs
	hasSentHeader bool
	hasRecvHeader bool
	buf           []byte
}

func (h *httpObfs) StreamConn(c net.Conn) net.Conn {
	return &httpConn{Conn: c, httpObfs: h}
}

func (c *httpConn) Read(b []byte) (int, error) {
	if c.buf != nil {
		n := copy(b, c.buf)
		if n == len(c.buf) {
			c.buf = nil
		} else {
			c.buf = c.buf[n:]
		}
		return n, nil
	}

	if c.hasRecvHeader {
		return c.Conn.Read(b)
	}

	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	pos := bytes.Index(buf[:n], []byte("\r\n\r\n"))
	if pos == -1 {
		return 0, io.EOF
	}
	c.hasRecvHeader = true
	dataLength := n - pos - 4
	n = copy(b, buf[4+pos:n])
	if dataLength > n {
		c.buf = append(c.buf, buf[4+pos+n:4+pos+dataLength]...)
	}
	return n, nil
}

func (c *httpConn) Write(b []byte) (int, error) {
	if c.hasSentHeader {
		return c.Conn.Write(b)
	}
	// 30: head length
	headLength := c.IVSize + 30

	bLength := len(b)
	headDataLength := bLength
	if bLength-headLength > 64 {
		headDataLength = headLength + rand.Intn(65)
	}
	headData := b[:headDataLength]
	b = b[headDataLength:]

	var body string
	host := c.Host
	if len(c.Param) > 0 {
		pos := strings.Index(c.Param, "#")
		if pos != -1 {
			body = strings.ReplaceAll(c.Param[pos+1:], "\n", "\r\n")
			body = strings.ReplaceAll(body, "\\n", "\r\n")
			host = c.Param[:pos]
		} else {
			host = c.Param
		}
	}
	hosts := strings.Split(host, ",")
	host = hosts[rand.Intn(len(hosts))]

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	if c.post {
		buf.WriteString("POST /")
	} else {
		buf.WriteString("GET /")
	}
	packURLEncodedHeadData(buf, headData)
	buf.WriteString(" HTTP/1.1\r\nHost: " + host)
	if c.Port != 80 {
		buf.WriteString(":" + strconv.Itoa(c.Port))
	}
	buf.WriteString("\r\n")
	if len(body) > 0 {
		buf.WriteString(body + "\r\n\r\n")
	} else {
		buf.WriteString("User-Agent: ")
		buf.WriteString(convert.RandUserAgent())
		buf.WriteString("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n")
		if c.post {
			packBoundary(buf)
		}
		buf.WriteString("DNT: 1\r\nConnection: keep-alive\r\n\r\n")
	}
	buf.Write(b)
	_, err := c.Conn.Write(buf.Bytes())
	if err != nil {
		return 0, nil
	}
	c.hasSentHeader = true
	return bLength, nil
}

func packURLEncodedHeadData(buf *bytes.Buffer, data []byte) {
	dataLength := len(data)
	for i := 0; i < dataLength; i++ {
		buf.WriteRune('%')
		buf.WriteString(hex.EncodeToString(data[i : i+1]))
	}
}

func packBoundary(buf *bytes.Buffer) {
	buf.WriteString("Content-Type: multipart/form-data; boundary=")
	set := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 32; i++ {
		buf.WriteByte(set[rand.Intn(62)])
	}
	buf.WriteString("\r\n")
}
