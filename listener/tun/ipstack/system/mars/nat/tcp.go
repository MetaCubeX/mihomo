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

	addr := c.RemoteAddr().(*net.TCPAddr)
	tup := t.table.tupleOf(uint16(addr.Port))
	if !addr.IP.Equal(t.portal.AsSlice()) || tup == zeroTuple {
		_ = c.Close()

		return nil, net.InvalidAddrError("unknown remote addr")
	}

	addition(c)

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

func (c *conn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.tuple.SourceAddr.Addr().AsSlice(),
		Port: int(c.tuple.SourceAddr.Port()),
	}
}

func (c *conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.tuple.DestinationAddr.Addr().AsSlice(),
		Port: int(c.tuple.DestinationAddr.Port()),
	}
}
