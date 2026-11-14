package fragment

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
)

// OOBStep says what to do with one of the first writes of a TCP connection.
type OOBStep struct {
	// Passthrough sends the write untouched.
	Passthrough bool
	// Byte is appended to the write and sent as TCP urgent (out-of-band) data.
	Byte byte
}

// ParseOOB parses a list like "0,_,12": one entry for each of the first writes of
// a connection, either the byte (0-255) to send as TCP urgent data right after that
// write, or "_" to leave that write untouched. An empty string means disabled.
func ParseOOB(s string) ([]OOBStep, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > 64 {
		return nil, fmt.Errorf("invalid tcp-oob %q: too many entries", s)
	}
	steps := make([]OOBStep, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "_" {
			steps = append(steps, OOBStep{Passthrough: true})
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("invalid tcp-oob %q: entries must be 0-255 or _", s)
		}
		steps = append(steps, OOBStep{Byte: byte(n)})
	}
	return steps, nil
}

// OOBConn appends one byte to each of the first writes and flags it as TCP urgent data.
// A peer handling urgent data the usual way drops that byte back out of the stream,
// while a middlebox mishandling the urgent pointer desyncs on those segments.
type OOBConn struct {
	N.ExtendedConn
	rawConn syscall.RawConn
	steps   []OOBStep

	access sync.Mutex
	index  int
	done   atomic.Bool
}

// NewOOBConn wraps c, which must be backed by a real TCP socket, otherwise c is returned as is.
func NewOOBConn(c net.Conn, steps []OOBStep) net.Conn {
	if !oobSupported || len(steps) == 0 {
		return c
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return c
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return c
	}
	return &OOBConn{ExtendedConn: N.NewExtendedConn(c), rawConn: rawConn, steps: steps}
}

func (c *OOBConn) Write(p []byte) (int, error) {
	if c.done.Load() {
		return c.ExtendedConn.Write(p)
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.index >= len(c.steps) {
		return c.ExtendedConn.Write(p)
	}
	step := c.steps[c.index]
	c.index++
	if c.index >= len(c.steps) {
		c.done.Store(true)
	}
	if step.Passthrough {
		return c.ExtendedConn.Write(p)
	}

	data := make([]byte, len(p)+1)
	copy(data, p)
	data[len(p)] = step.Byte

	var sent int
	var sendErr error
	err := c.rawConn.Write(func(fd uintptr) bool {
		sent, sendErr = sendOOB(fd, data)
		// socket not writable yet: wait and send again
		return sendErr != syscall.EAGAIN && sendErr != syscall.EWOULDBLOCK
	})
	if err == nil {
		err = sendErr
	}
	if err != nil {
		// urgent data is not supported by this socket (like mptcp), send the write as is
		return c.ExtendedConn.Write(p)
	}
	if sent >= len(p) { // the extra byte is ours, never report it
		return len(p), nil
	}
	// a short send is unlikely on these leading writes, deliver the rest the normal way
	n, err := c.ExtendedConn.Write(p[sent:])
	return sent + n, err
}

func (c *OOBConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.done.Load() {
		return c.ExtendedConn.WriteBuffer(buffer)
	}
	defer buffer.Release()
	_, err := c.Write(buffer.Bytes())
	return err
}

func (c *OOBConn) Upstream() any {
	return c.ExtendedConn
}

func (c *OOBConn) ReaderReplaceable() bool {
	return true
}

func (c *OOBConn) WriterReplaceable() bool {
	return c.done.Load()
}
