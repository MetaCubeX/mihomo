package utils

import (
	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/randv2"
)

type unsafeRandReader struct{}

func (r unsafeRandReader) Read(p []byte) (n int, err error) {
	// modify from https://github.com/golang/go/blob/587c3847da81aa7cfc3b3db2677c8586c94df13a/src/runtime/rand.go#L70-L89
	// Inspired by wyrand.
	n = len(p)
	v := randv2.Uint64()
	for len(p) > 0 {
		v ^= 0xa0761d6478bd642f
		v *= 0xe7037ed1a0b428db
		size := 8
		if len(p) < 8 {
			size = len(p)
		}
		for i := 0; i < size; i++ {
			p[i] ^= byte(v >> (8 * i))
		}
		p = p[size:]
		v = v>>32 | v<<32
	}

	return
}

var UnsafeRandReader = unsafeRandReader{}

var UnsafeUUIDGenerator = uuid.NewGenWithOptions(uuid.WithRandomReader(UnsafeRandReader))

func NewUUIDV1() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV1() // unsafeRandReader wouldn't cause error, so ignore err is safe
	return u
}

func NewUUIDV3(ns uuid.UUID, name string) uuid.UUID {
	return UnsafeUUIDGenerator.NewV3(ns, name)
}

func NewUUIDV4() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV4() // unsafeRandReader wouldn't cause error, so ignore err is safe
	return u
}

func NewUUIDV5(ns uuid.UUID, name string) uuid.UUID {
	return UnsafeUUIDGenerator.NewV5(ns, name)
}

func NewUUIDV6() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV6() // unsafeRandReader wouldn't cause error, so ignore err is safe
	return u
}

func NewUUIDV7() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV7() // unsafeRandReader wouldn't cause error, so ignore err is safe
	return u
}

// UUIDMap https://github.com/XTLS/Xray-core/issues/158#issue-783294090
func UUIDMap(str string) (uuid.UUID, error) {
	u, err := uuid.FromString(str)
	if err != nil {
		return NewUUIDV5(uuid.Nil, str), nil
	}
	return u, nil
}
