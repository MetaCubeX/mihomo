package xhttp

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
	httputils.NetAddr

	// client: Close lets the upload finish before tearing the requests down
	linger     bool
	lingerOnce sync.Once

	// deadlines
	deadline *time.Timer
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// closeLinger bounds how long a closed client conn may still finish.
const closeLinger = 5 * time.Second

func (c *Conn) Close() error {
	err := c.writer.Close() // the upload ends here, after the data
	if c.linger {
		// Closing the download, the transport or the request context at once
		// resets the streams: the tail of the upload (or all of a short one,
		// VLESS header included) was lost. Let the server see the end of the
		// upload and finish the download first.
		c.lingerOnce.Do(func() { go c.lingerClose() })
		return err
	}
	return errors.Join(err, c.teardown())
}

func (c *Conn) lingerClose() {
	force := time.AfterFunc(closeLinger, func() { _ = c.teardown() })
	_, _ = io.Copy(io.Discard, c.reader)
	if force.Stop() {
		_ = c.teardown()
	}
}

func (c *Conn) teardown() error {
	err := c.reader.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return err
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
