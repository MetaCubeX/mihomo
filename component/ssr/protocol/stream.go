package protocol

import (
	"bytes"
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

// NewConn wraps a stream-oriented net.Conn with protocol decoding/encoding
func NewConn(c net.Conn, p Protocol, iv []byte) net.Conn {
	return &Conn{Conn: c, Protocol: p.initForConn(iv)}
}

// Conn represents a protocol connection
type Conn struct {
	net.Conn
	Protocol
	buf          []byte
	offset       int
	underDecoded bytes.Buffer
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.buf != nil {
		n := copy(b, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			c.buf = nil
		}
		return n, nil
	}
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	c.underDecoded.Write(buf[:n])
	underDecoded := c.underDecoded.Bytes()
	decoded, length, err := c.Decode(underDecoded)
	if err != nil {
		c.underDecoded.Reset()
		return 0, nil
	}
	if length == 0 {
		return 0, nil
	}
	c.underDecoded.Next(length)
	n = copy(b, decoded)
	if len(decoded) > len(b) {
		c.buf = decoded
		c.offset = n
	}
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	encoded, err := c.Encode(b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(encoded)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
