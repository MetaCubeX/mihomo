package obfs

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

// NewConn wraps a stream-oriented net.Conn with obfs decoding/encoding
func NewConn(c net.Conn, o Obfs) net.Conn {
	return &Conn{Conn: c, Obfs: o.initForConn()}
}

// Conn represents an obfs connection
type Conn struct {
	net.Conn
	Obfs
	buf    []byte
	offset int
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.buf != nil {
		n := copy(b, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
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
	decoded, sendback, err := c.Decode(buf[:n])
	// decoded may be part of buf
	decodedData := pool.Get(len(decoded))
	copy(decodedData, decoded)
	if err != nil {
		pool.Put(decodedData)
		return 0, err
	}
	if sendback {
		c.Write(nil)
		pool.Put(decodedData)
		return 0, nil
	}
	n = copy(b, decodedData)
	if len(decodedData) > len(b) {
		c.buf = decodedData
		c.offset = n
	} else {
		pool.Put(decodedData)
	}
	return n, err
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
