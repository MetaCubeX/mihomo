package utils

import (
	"github.com/gofrs/uuid"
	"github.com/zhangyunhao116/fastrand"
)

type fastRandReader struct{}

func (r fastRandReader) Read(p []byte) (int, error) {
	return fastrand.Read(p)
}

var UnsafeUUIDGenerator = uuid.NewGenWithOptions(uuid.WithRandomReader(fastRandReader{}))

func NewUUIDV1() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV1() // fastrand.Read wouldn't cause error, so ignore err is safe
	return u
}

func NewUUIDV3(ns uuid.UUID, name string) uuid.UUID {
	return UnsafeUUIDGenerator.NewV3(ns, name)
}

func NewUUIDV4() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV4() // fastrand.Read wouldn't cause error, so ignore err is safe
	return u
}

func NewUUIDV5(ns uuid.UUID, name string) uuid.UUID {
	return UnsafeUUIDGenerator.NewV5(ns, name)
}

func NewUUIDV6() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV6() // fastrand.Read wouldn't cause error, so ignore err is safe
	return u
}

func NewUUIDV7() uuid.UUID {
	u, _ := UnsafeUUIDGenerator.NewV7() // fastrand.Read wouldn't cause error, so ignore err is safe
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
