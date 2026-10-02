package nowhere

import (
	"net"
	"sync"
	"time"

	quic "github.com/metacubex/quic-go"
)

type quicStream struct {
	*quic.Stream
	conn *quic.Conn
	wmu  sync.Mutex
}

func (s *quicStream) Write(b []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.Stream.Write(b)
}
func (s *quicStream) Close() error {
	s.CancelRead(0)
	// Interrupt an in-flight Write before closing the send side. Keep bytes
	// already accepted by QUIC (notably SetupResult) queued for delivery.
	_ = s.Stream.SetWriteDeadline(time.Now())
	return s.CloseWrite()
}
func (s *quicStream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.Stream.Close()
}
func (s *quicStream) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *quicStream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

type lane struct {
	net.Conn
	q *quicSession
}
type flowConn struct {
	reader, writer *lane
	once           sync.Once
	release        func()
	done           chan struct{}
}

func (c *flowConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *flowConn) Write(b []byte) (int, error) { return c.writer.Write(b) }
func (c *flowConn) lanes() []*lane {
	if c.reader == c.writer {
		return []*lane{c.reader}
	}
	return []*lane{c.reader, c.writer}
}
func (c *flowConn) Close() error {
	c.once.Do(func() {
		if c.done != nil {
			close(c.done)
		}
		for _, l := range c.lanes() {
			l.Close()
		}
		if c.release != nil {
			c.release()
		}
	})
	return nil
}
func (c *flowConn) watchCarriers() {
	for _, l := range c.lanes() {
		var done <-chan struct{}
		if l.q != nil {
			done = l.q.conn.Context().Done()
		} else if stream, ok := l.Conn.(*muxStream); ok {
			done = stream.m.done
		}
		if done != nil {
			go func() {
				select {
				case <-done:
					c.Close()
				case <-c.done:
				}
			}()
		}
	}
}
func (c *flowConn) CloseWrite() error {
	if w, ok := c.writer.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func (c *flowConn) LocalAddr() net.Addr  { return c.reader.LocalAddr() }
func (c *flowConn) RemoteAddr() net.Addr { return c.reader.RemoteAddr() }
func (c *flowConn) SetDeadline(t time.Time) error {
	for _, l := range c.lanes() {
		if err := l.SetDeadline(t); err != nil {
			return err
		}
	}
	return nil
}
func (c *flowConn) SetReadDeadline(t time.Time) error  { return c.reader.SetReadDeadline(t) }
func (c *flowConn) SetWriteDeadline(t time.Time) error { return c.writer.SetWriteDeadline(t) }
