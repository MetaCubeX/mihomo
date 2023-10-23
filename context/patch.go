package context

import "net"

func (c *ConnContext) RawConn() (net.Conn, bool) {
	return c.conn, true
}
