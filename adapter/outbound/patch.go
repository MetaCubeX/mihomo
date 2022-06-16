package outbound

import "net"

func (c *conn) RawConn() (net.Conn, bool) {
	return c.Conn, true
}
