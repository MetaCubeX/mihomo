package callback

import (
	C "github.com/Dreamacro/clash/constant"
)

type FirstWriteCallBackConn struct {
	C.Conn
	Callback func(error)
	written  bool
}

func (c *FirstWriteCallBackConn) Write(b []byte) (n int, err error) {
	defer func() {
		if !c.written {
			c.written = true
			c.Callback(err)
		}
	}()
	return c.Conn.Write(b)
}

func (c *FirstWriteCallBackConn) Upstream() any {
	return c.Conn
}
