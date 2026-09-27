package crypto

import (
	"io"
	"net"

	"github.com/metacubex/mihomo/transport/sudoku/connutil"
)

func (c *RecordConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if c.method == "none" {
		return connutil.Copy(w, c.Conn)
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var total int64
	for {
		if c.readOff >= len(c.readPlain) {
			c.readPlain, c.readOff = nil, 0
			if _, err := c.readLocked(nil); err != nil {
				if err == io.EOF {
					return total, nil
				}
				return total, err
			}
			if len(c.readPlain) == 0 {
				continue
			}
		}
		p := c.readPlain[c.readOff:]
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			n, err = 0, io.ErrShortWrite
		}
		if n < len(p) && err == nil {
			err = io.ErrShortWrite
		}
		c.readOff += n
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
}
