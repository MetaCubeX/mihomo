package nat

import (
	"net"
	"net/netip"
	"time"
)

type TCP struct {
	listener *net.TCPListener
	portal   netip.Addr
	table    *table
}

type conn struct {
	net.Conn

	tuple tuple
}

func (t *TCP) Accept() (net.Conn, error) {
	c, err := t.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	addr := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	tup := t.table.tupleOf(addr.Port())
	if addr.Addr() != t.portal || tup == zeroTuple {
		_ = c.Close()

		return nil, net.InvalidAddrError("unknown remote addr")
	}

	addition(c)

	_ = c.SetLinger(0)

	return &conn{
		Conn:  c,
		tuple: tup,
	}, nil
}

func (t *TCP) Close() error {
	return t.listener.Close()
}

func (t *TCP) Addr() net.Addr {
	return t.listener.Addr()
}

func (t *TCP) SetDeadline(time time.Time) error {
	return t.listener.SetDeadline(time)
}

func (c *conn) Close() error {
	return c.Conn.Close()
}

func (c *conn) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(c.tuple.SourceAddr)
}

func (c *conn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(c.tuple.DestinationAddr)
}
