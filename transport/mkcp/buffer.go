package mkcp

import (
	"errors"
	"io"
	"sync"
)

// bufSize is the size of a regular buffer, matching xray-core's buf.Size so that
// a single buffer always fits one UDP datagram worth of mKCP payload.
const bufSize = 8192

var errBufferFull = errors.New("buffer is full")

var pool = sync.Pool{New: func() any { return make([]byte, bufSize) }}

// Buffer is a recyclable fixed-capacity byte buffer, a trimmed port of
// xray-core's common/buf.Buffer holding only the methods the mKCP core needs.
type Buffer struct {
	v     []byte
	start int32
	end   int32
}

// New creates a Buffer with 0 length and bufSize capacity.
func New() *Buffer {
	return &Buffer{v: pool.Get().([]byte)}
}

// StackNew creates a Buffer value (intended to be released in the same function).
func StackNew() Buffer {
	return Buffer{v: pool.Get().([]byte)}
}

// Release recycles the underlying byte array into the pool.
func (b *Buffer) Release() {
	if b == nil || b.v == nil {
		return
	}
	p := b.v
	b.v = nil
	b.Clear()
	if cap(p) >= bufSize {
		pool.Put(p[:bufSize])
	}
}

// Clear resets the buffer to empty without releasing the array.
func (b *Buffer) Clear() {
	b.start = 0
	b.end = 0
}

// Bytes returns the content of the buffer.
func (b *Buffer) Bytes() []byte {
	return b.v[b.start:b.end]
}

// Extend grows the buffer by n bytes and returns the (zeroed) extended part.
func (b *Buffer) Extend(n int32) []byte {
	end := b.end + n
	if end > int32(len(b.v)) {
		panic("mkcp: extending out of bound")
	}
	ext := b.v[b.end:end]
	b.end = end
	for i := range ext {
		ext[i] = 0
	}
	return ext
}

// BytesFrom returns the content of the buffer starting at the given position.
func (b *Buffer) BytesFrom(from int32) []byte {
	if from < 0 {
		from += b.Len()
	}
	return b.v[b.start+from : b.end]
}

// Len returns the length of the content.
func (b *Buffer) Len() int32 {
	if b == nil {
		return 0
	}
	return b.end - b.start
}

// IsEmpty returns true if the buffer has no content.
func (b *Buffer) IsEmpty() bool {
	return b.Len() == 0
}

// IsFull returns true if the buffer cannot grow further.
func (b *Buffer) IsFull() bool {
	return b != nil && b.end == int32(len(b.v))
}

// Write appends data into the buffer.
func (b *Buffer) Write(data []byte) (int, error) {
	n := copy(b.v[b.end:], data)
	b.end += int32(n)
	if n < len(data) {
		return n, errBufferFull
	}
	return n, nil
}

// Read implements io.Reader, draining from the front of the buffer.
func (b *Buffer) Read(data []byte) (int, error) {
	if b.Len() == 0 {
		return 0, io.EOF
	}
	n := copy(data, b.v[b.start:b.end])
	if int32(n) == b.Len() {
		b.Clear()
	} else {
		b.start += int32(n)
	}
	return n, nil
}

// ReadFrom reads once from reader into the free space of the buffer.
func (b *Buffer) ReadFrom(reader io.Reader) (int64, error) {
	n, err := reader.Read(b.v[b.end:])
	b.end += int32(n)
	return int64(n), err
}

// ReadFullFrom reads exactly size bytes from reader, or until an error occurs.
func (b *Buffer) ReadFullFrom(reader io.Reader, size int32) (int64, error) {
	end := b.end + size
	if end > int32(len(b.v)) {
		return 0, errors.New("mkcp: read out of bound")
	}
	n, err := io.ReadFull(reader, b.v[b.end:end])
	b.end += int32(n)
	return int64(n), err
}

// MultiBuffer is an ordered list of Buffers.
type MultiBuffer []*Buffer

// ReleaseMulti releases all buffers and returns an emptied slice.
func ReleaseMulti(mb MultiBuffer) MultiBuffer {
	for i := range mb {
		mb[i].Release()
		mb[i] = nil
	}
	return mb[:0]
}

// IsEmpty returns true if the MultiBuffer holds no content.
func (mb MultiBuffer) IsEmpty() bool {
	for _, b := range mb {
		if !b.IsEmpty() {
			return false
		}
	}
	return true
}

// SplitBytes copies bytes from the front of the MultiBuffer into b, releasing
// drained buffers, and returns the leftover MultiBuffer and bytes written.
func SplitBytes(mb MultiBuffer, b []byte) (MultiBuffer, int) {
	totalBytes := 0
	endIndex := -1
	for i := range mb {
		pBuffer := mb[i]
		nBytes, _ := pBuffer.Read(b)
		totalBytes += nBytes
		b = b[nBytes:]
		if !pBuffer.IsEmpty() {
			endIndex = i
			break
		}
		pBuffer.Release()
		mb[i] = nil
	}
	if endIndex == -1 {
		mb = mb[:0]
	} else {
		mb = mb[endIndex:]
	}
	return mb, totalBytes
}

// MultiBufferContainer wraps a MultiBuffer as an io.ReadCloser.
type MultiBufferContainer struct {
	MultiBuffer
}

// Read implements io.Reader.
func (c *MultiBufferContainer) Read(b []byte) (int, error) {
	if c.MultiBuffer.IsEmpty() {
		return 0, io.EOF
	}
	mb, nBytes := SplitBytes(c.MultiBuffer, b)
	c.MultiBuffer = mb
	return nBytes, nil
}

// Close implements io.Closer.
func (c *MultiBufferContainer) Close() error {
	c.MultiBuffer = ReleaseMulti(c.MultiBuffer)
	return nil
}
