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

func newReadBuffer(size int) []byte {
	newSize := uint(1) << bits.Len(uint(size-1))
	if newSize > ^uint(0)>>1 {
		newSize = uint(size)
	}
	return make([]byte, int(newSize))
}

// Grow increases the read buffer to at least size while preserving buffered data.
// The capacity grows geometrically to avoid repeated allocations for small increments.
func (c *BufferedConn) Grow(size int) {
	b := (*bufioReader)(unsafe.Pointer(c.r))
	if size <= len(b.buf) {
		return
	}

	newBuf := newReadBuffer(size)
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

// PrependData inserts buf before all unread data.
func (c *BufferedConn) PrependData(buf []byte) {
	if len(buf) == 0 {
		return
	}

	b := (*bufioReader)(unsafe.Pointer(c.r))
	if len(buf) <= b.r {
		// Reuse the consumed space before the unread data without moving it.
		b.r -= len(buf)
		copy(b.buf[b.r:], buf)
	} else {
		buffered := b.w - b.r
		needed := buffered + len(buf)
		if needed > len(b.buf) {
			// Build the final layout directly instead of copying the unread data
			// once in Grow and again to make room for buf.
			newBuf := newReadBuffer(needed)
			copy(newBuf, buf)
			copy(newBuf[len(buf):], b.buf[b.r:b.w])
			b.buf = newBuf
		} else {
			// Shift the unread data right to make room at the beginning.
			copy(b.buf[len(buf):], b.buf[b.r:b.w])
			copy(b.buf, buf)
		}
		b.r = 0
		b.w = needed
	}
	b.lastByte = -1
	b.lastRuneSize = -1
}
