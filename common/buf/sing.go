package buf

import (
	"github.com/metacubex/sing/common/buf"
)

const BufferSize = buf.BufferSize

type Buffer = buf.Buffer

func New() *Buffer {
	return buf.New()
}

func NewPacket() *Buffer {
	return buf.NewPacket()
}

func NewSize(size int) *Buffer {
	return buf.NewSize(size)
}

func With(data []byte) *Buffer {
	return buf.With(data)
}

func As(data []byte) *Buffer {
	return buf.As(data)
}

func ReleaseMulti(buffers []*Buffer) {
	buf.ReleaseMulti(buffers)
}

func Error(_ any, err error) error {
	return err
}

func Must(errs ...error) {
	for _, err := range errs {
		if err != nil {
			panic(err)
		}
	}
}

func Must1[T any](result T, err error) T {
	if err != nil {
		panic(err)
	}
	return result
}

func Must2[T any, T2 any](result T, result2 T2, err error) (T, T2) {
	if err != nil {
		panic(err)
	}
	return result, result2
}
