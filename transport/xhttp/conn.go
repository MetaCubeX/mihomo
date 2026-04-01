package xhttp

import (
	"errors"
	"io"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
	httputils.NetAddr

	// deadlines
	deadline *time.Timer
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *Conn) Close() error {
	err := c.writer.Close()
	err2 := c.reader.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return errors.Join(err, err2)
}

func (c *Conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *Conn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		if c.deadline != nil {
			c.deadline.Stop()
			c.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if c.deadline != nil {
		c.deadline.Reset(d)
		return nil
	}
	c.deadline = time.AfterFunc(d, func() {
		c.Close()
	})
	return nil
}
