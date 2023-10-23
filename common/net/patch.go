package net

import "net"

func (c *BufferedConn) RawConn() (net.Conn, bool) {
	if c.r.Buffered() == 0 {
		return c.ExtendedConn, true
	}

	return nil, false
}
