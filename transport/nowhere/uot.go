package nowhere

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/pool"
)

// uotReader retains only a partially read header or payload across deadlines.
// Complete packets are read directly into the caller's buffer when it fits.
// The owning packetConn serializes reads and clears this state on close.
type uotReader struct {
	header [2]byte
	head   int
	prefix []byte
	err    error
}

func (u *uotReader) read(r io.Reader, b []byte) (int, error) {
	if u.err != nil {
		return 0, u.err
	}
	if u.head < len(u.header) {
		n, err := io.ReadFull(r, u.header[u.head:])
		u.head += n
		if err != nil {
			if err == io.EOF && u.head != 0 {
				err = io.ErrUnexpectedEOF
			}
			return 0, u.readError(err)
		}
	}
	size := int(binary.BigEndian.Uint16(u.header[:]))
	data := b
	if size > len(b) {
		data = pool.Get(size)
		defer pool.Put(data)
	}
	data = data[:size]
	have := copy(data, u.prefix)
	n, err := io.ReadFull(r, data[have:])
	if err != nil {
		// Once the header announces a nonempty payload, even an EOF before
		// its first byte is a truncated frame, not clean end-of-stream.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		u.readError(err)
		if u.err == nil {
			// The caller may reuse b after a timeout; never retain its storage.
			u.prefix = append(u.prefix[:0], data[:have+n]...)
		}
		return 0, err
	}
	u.head = 0
	u.prefix = nil
	if size > len(b) {
		return copy(b, data), io.ErrShortBuffer
	}
	return size, nil
}

func (u *uotReader) readError(err error) error {
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		u.err = err
		u.prefix = nil
	}
	return err
}
