package utils

import (
	"github.com/gofrs/uuid"
)

var uuidNamespace, _ = uuid.FromString("00000000-0000-0000-0000-000000000000")

// UUIDMap https://github.com/XTLS/Xray-core/issues/158#issue-783294090
func UUIDMap(str string) (uuid.UUID, error) {
	u, err := uuid.FromString(str)
	if err != nil {
		return uuid.NewV5(uuidNamespace, str), nil
	}
	return u, nil
}
