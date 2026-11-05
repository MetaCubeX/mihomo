package sudoku

import (
	"io"

	"github.com/metacubex/mihomo/common/pool"
)

const (
	// smallReadSize is what a connection reads into while it may block for a
	// long time. Idle connections hold at most this much.
	smallReadSize = 512
	// readBufferSize is the wire read size of a busy connection, borrowed from
	// the shared pool only while it has data.
	readBufferSize = 32 * 1024
)

// wireReader hands the codecs the raw bytes already received, without a second
// copy. It reads small while a connection is quiet, switches to a pooled buffer
// once a read fills its buffer (more is queued, so the next read will not
// block), and returns that buffer when drained.
type wireReader struct {
	src      io.Reader
	buf      []byte
	pooled   bool
	r, w     int
	wasFull  bool
	smallBuf [smallReadSize]byte
}

// peek borrows every unread wire byte, reading first when there are none. It
// waits for at least one byte, never for a full buffer. The slice is valid
// until the next peek or discard.
func (wr *wireReader) peek() ([]byte, error) {
	if wr.r == wr.w {
		if err := wr.fill(); err != nil {
			return nil, err
		}
	}
	return wr.buf[wr.r:wr.w], nil
}

func (wr *wireReader) fill() error {
	switch {
	case wr.wasFull && !wr.pooled:
		wr.buf, wr.pooled = pool.Get(readBufferSize), true
	case wr.buf == nil:
		wr.buf = wr.smallBuf[:]
	}
	for {
		n, err := wr.src.Read(wr.buf)
		if n > 0 {
			wr.r, wr.w = 0, n
			wr.wasFull = n == len(wr.buf)
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// discard drops n bytes peek returned. A pooled buffer goes back once it is
// drained by a read that did not fill it, since the next read may block.
func (wr *wireReader) discard(n int) {
	wr.r += n
	if wr.r == wr.w && wr.pooled && !wr.wasFull {
		pool.Put(wr.buf)
		wr.buf, wr.pooled = wr.smallBuf[:], false
		wr.r, wr.w = 0, 0
	}
}

// pending returns the received but undecoded bytes.
func (wr *wireReader) pending() []byte {
	if wr == nil {
		return nil
	}
	return wr.buf[wr.r:wr.w]
}
