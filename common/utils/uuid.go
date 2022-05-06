package utils

import (
	"crypto/sha1"
	"encoding/hex"
	"github.com/gofrs/uuid"
)

// UUIDMap https://github.com/XTLS/Xray-core/issues/158#issue-783294090
func UUIDMap(str string) (uuid.UUID, error) {
	u, err := uuid.FromString(str)
	if err != nil {
		var Nil [16]byte
		h := sha1.New()
		h.Write(Nil[:])
		h.Write([]byte(str))
		u := h.Sum(nil)[:16]
		u[6] = (u[6] & 0x0f) | (5 << 4)
		u[8] = u[8]&(0xff>>2) | (0x02 << 6)
		buf := make([]byte, 36)
		hex.Encode(buf[0:8], u[0:4])
		buf[8] = '-'
		hex.Encode(buf[9:13], u[4:6])
		buf[13] = '-'
		hex.Encode(buf[14:18], u[6:8])
		buf[18] = '-'
		hex.Encode(buf[19:23], u[8:10])
		buf[23] = '-'
		hex.Encode(buf[24:], u[10:])
		return uuid.FromString(string(buf))
	}
	return u, nil
}
