package memconservative

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

var (
	errFailedToReadBytes            = errors.New("failed to read bytes")
	errFailedToReadExpectedLenBytes = errors.New("failed to read expected length of bytes")
	errInvalidGeodataFile           = errors.New("invalid geodata file")
	errInvalidGeodataVarintLength   = errors.New("invalid geodata varint length")
	errCodeNotFound                 = errors.New("code not found")
)

func emitBytes(f io.ReadSeeker, code string) ([]byte, error) {
	reader := bufio.NewReaderSize(f, 64*1024)
	readError := func(err error) error {
		switch err {
		case io.EOF:
			return errCodeNotFound
		case io.ErrUnexpectedEOF:
			return errFailedToReadExpectedLenBytes
		default:
			return errFailedToReadBytes
		}
	}
	var lengthBytes []byte
	readLength := func() (uint64, error) {
		lengthBytes = lengthBytes[:0]
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return 0, readError(err)
			}
			lengthBytes = append(lengthBytes, b)
			if b < 128 {
				n, size := protowire.ConsumeVarint(lengthBytes)
				if size < 0 {
					return 0, errInvalidGeodataVarintLength
				}
				return n, nil
			}
		}
	}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, readError(err)
		}
		if b != 10 {
			return nil, errInvalidGeodataFile
		}
		length, err := readLength()
		if err != nil {
			return nil, err
		}
		b, err = reader.ReadByte()
		if err != nil {
			return nil, readError(err)
		}
		if b != 10 {
			return nil, errInvalidGeodataFile
		}
		codeLength, err := readLength()
		if err != nil {
			return nil, err
		}
		name := make([]byte, codeLength)
		if _, err := io.ReadFull(reader, name); err != nil {
			return nil, readError(err)
		}
		prefixLength := 1 + uint64(len(lengthBytes)) + codeLength
		if strings.EqualFold(string(name), code) {
			result := make([]byte, length)
			n := copy(result, []byte{10})
			n += copy(result[n:], lengthBytes)
			n += copy(result[n:], name)
			if _, err := io.ReadFull(reader, result[n:]); err != nil {
				return nil, readError(err)
			}
			return result, nil
		}
		offset := int64(length) - int64(prefixLength)
		if offset >= 0 && offset <= int64(reader.Buffered()) {
			_, err = reader.Discard(int(offset))
		} else {
			_, err = f.Seek(offset-int64(reader.Buffered()), io.SeekCurrent)
			reader.Reset(f)
		}
		if err != nil {
			return nil, errFailedToReadBytes
		}
	}
}

func Decode(filename, code string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	geoBytes, err := emitBytes(f, code)
	if err != nil {
		return nil, err
	}
	return geoBytes, nil
}
