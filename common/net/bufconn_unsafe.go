package net

import (
	"io"
	"unsafe"
)

// bufioReader copy from stdlib bufio/bufio.go
// This structure has remained unchanged from go1.5 to go1.21.
type bufioReader struct {
	buf          []byte
	rd           io.Reader // reader provided by the client
	r, w         int       // buf read and write positions
	err          error
	lastByte     int // last byte read for UnreadByte; -1 means invalid
	lastRuneSize int // size of last rune read for UnreadRune; -1 means invalid
}

func (c *BufferedConn) AppendData(buf []byte) (ok bool) {
	b := (*bufioReader)(unsafe.Pointer(c.r))
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
