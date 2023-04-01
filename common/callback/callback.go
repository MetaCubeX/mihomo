package callback

import (
	"github.com/Dreamacro/clash/common/buf"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
)

type firstWriteCallBackConn struct {
	C.Conn
	callback func(error)
	written  bool
}

func (c *firstWriteCallBackConn) Write(b []byte) (n int, err error) {
	defer func() {
		if !c.written {
			c.written = true
			c.callback(err)
		}
	}()
	return c.Conn.Write(b)
}

func (c *firstWriteCallBackConn) Upstream() any {
	return c.Conn
}

type extendedConn interface {
	C.Conn
	N.ExtendedConn
}

type firstWriteCallBackExtendedConn struct {
	extendedConn
	callback func(error)
	written  bool
}

func (c *firstWriteCallBackExtendedConn) Write(b []byte) (n int, err error) {
	defer func() {
		if !c.written {
			c.written = true
			c.callback(err)
		}
	}()
	return c.extendedConn.Write(b)
}

func (c *firstWriteCallBackExtendedConn) WriteBuffer(buffer *buf.Buffer) (err error) {
	defer func() {
		if !c.written {
			c.written = true
			c.callback(err)
		}
	}()
	return c.extendedConn.WriteBuffer(buffer)
}

func (c *firstWriteCallBackExtendedConn) Upstream() any {
	return c.extendedConn
}

func NewFirstWriteCallBackConn(c C.Conn, callback func(error)) C.Conn {
	if c, ok := c.(extendedConn); ok {
		return &firstWriteCallBackExtendedConn{
			extendedConn: c,
			callback:     callback,
			written:      false,
		}
	}
	return &firstWriteCallBackConn{
		Conn:     c,
		callback: callback,
		written:  false,
	}
}
