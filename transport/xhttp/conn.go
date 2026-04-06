package xhttp

import (
	"io"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
	httputils.NetAddr
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
	if err != nil {
		return err
	}
	return err2
}

func (c *Conn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *Conn) SetDeadline(_ time.Time) error      { return nil }
