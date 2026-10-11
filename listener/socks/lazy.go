package socks

import (
	"net"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/once"
)

// lazyConn defers the reply to a CONNECT request until the tunnel reports the result of
// connecting to the target, so the client sees the real connect latency and failures.
// Reading or writing before that implies success, so inbound-side readers such as the sniffer
// keep working and just get an early reply, and closing before that implies failure.
type lazyConn struct {
	net.Conn
	reply    func(err error) error // writes the reply, err is nil on success
	once     sync.Once
	replyErr error
}

func newLazyConn(conn net.Conn, reply func(err error) error) *lazyConn {
	return &lazyConn{Conn: conn, reply: reply}
}

func (c *lazyConn) writeReply(err error) error {
	c.once.Do(func() {
		c.replyErr = c.reply(err)
	})
	return c.replyErr
}

// HandshakeSuccess implements N.HandshakeSuccess
func (c *lazyConn) HandshakeSuccess() error {
	return c.writeReply(nil)
}

// HandshakeFailure implements N.HandshakeFailure
func (c *lazyConn) HandshakeFailure(err error) error {
	return c.writeReply(err)
}

// NeedReportHandshake implements N.LazyConn
func (c *lazyConn) NeedReportHandshake() bool {
	return !once.Done(&c.once)
}

func (c *lazyConn) Read(b []byte) (int, error) {
	if err := c.writeReply(nil); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *lazyConn) Write(b []byte) (int, error) {
	if err := c.writeReply(nil); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *lazyConn) Close() error {
	_ = c.writeReply(net.ErrClosed)
	return c.Conn.Close()
}

func (c *lazyConn) Upstream() any {
	return c.Conn
}

func (c *lazyConn) ReaderReplaceable() bool {
	return once.Done(&c.once)
}

func (c *lazyConn) WriterReplaceable() bool {
	return once.Done(&c.once)
}

var _ N.LazyConn = (*lazyConn)(nil)
var _ N.HandshakeSuccess = (*lazyConn)(nil)
var _ N.HandshakeFailure = (*lazyConn)(nil)
