package net

import (
	"io"
	"math/bits"
	"unsafe"
)

// bufioReader copy from stdlib bufio/bufio.go
// This structure has remained unchanged from go1.5 to go1.26.
type bufioReader struct {
	buf          []byte
	rd           io.Reader // reader provided by the client
	r, w         int       // buf read and write positions
	err          error
	lastByte     int // last byte read for UnreadByte; -1 means invalid
	lastRuneSize int // size of last rune read for UnreadRune; -1 means invalid
}

// Grow increases the read buffer to at least size while preserving buffered data.
// The capacity grows geometrically to avoid repeated allocations for small increments.
func (c *BufferedConn) Grow(size int) {
	b := (*bufioReader)(unsafe.Pointer(c.r))
	if size <= len(b.buf) {
		return
	}

	newSize := uint(1) << bits.Len(uint(size-1))
	if newSize > ^uint(0)>>1 {
		newSize = uint(size)
	}

	newBuf := make([]byte, int(newSize))
	buffered := copy(newBuf, b.buf[b.r:b.w])
	b.buf = newBuf
	b.r = 0
	b.w = buffered
}

func (c *BufferedConn) AppendData(buf []byte) (ok bool) {
	b := (*bufioReader)(unsafe.Pointer(c.r))
	needed := b.w - b.r + len(buf)
	if needed > len(b.buf) {
		c.Grow(needed)
	}
	pos := len(b.buf) - b.w - len(buf)
	if pos >= -b.r { // len(b.buf)-(b.w - b.r) >= len(buf)
		if pos < 0 { // len(b.buf)-b.w < len(buf)
			// Slide existing data to beginning.
			copy(b.buf, b.buf[b.r:b.w])
			b.w -= b.r
			b.r = 0
		}

		b.w += copy(b.buf[b.w:], buf)
		return true
	}
	return false
}
