package gun

import (
	"encoding/binary"
	"io"
)

type stubByteReader struct {
	io.Reader
}

func (r stubByteReader) ReadByte() (byte, error) {
	var b [1]byte
	var n int
	var err error
	for n == 0 && err == nil {
		n, err = r.Read(b[:])
	}

	if n == 1 && err == io.EOF {
		err = nil
	}
	return b[0], err
}

func ToByteReader(reader io.Reader) io.ByteReader {
	if byteReader, ok := reader.(io.ByteReader); ok {
		return byteReader
	}
	return &stubByteReader{reader}
}

func ReadUVariant(reader io.Reader) (uint64, error) {
	return binary.ReadUvarint(ToByteReader(reader))
}

func UVarintLen(x uint64) int {
	switch {
	case x < 1<<(7*1):
		return 1
	case x < 1<<(7*2):
		return 2
	case x < 1<<(7*3):
		return 3
	case x < 1<<(7*4):
		return 4
	case x < 1<<(7*5):
		return 5
	case x < 1<<(7*6):
		return 6
	case x < 1<<(7*7):
		return 7
	case x < 1<<(7*8):
		return 8
	case x < 1<<(7*9):
		return 9
	default:
		return 10
	}
}
