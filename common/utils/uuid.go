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

// UUIDMap https://github.com/XTLS/Xray-core/issues/158#issue-783294090
func UUIDMap(str string) (uuid.UUID, error) {
	u, err := uuid.FromString(str)
	if err != nil {
		return UnsafeUUIDGenerator.NewV5(uuid.Nil, str), nil
	}
	return u, nil
}
