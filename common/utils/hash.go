package utils

import (
	"crypto/md5"
	"encoding/hex"
)

// HashType warps hash array inside struct
// someday can change to other hash algorithm simply
type HashType struct {
	md5 [md5.Size]byte // MD5
}

func MakeHash(data []byte) HashType {
	return HashType{md5.Sum(data)}
}

func MakeHashFromBytes(hashBytes []byte) (h HashType) {
	if len(hashBytes) != md5.Size {
		return
	}
	copy(h.md5[:], hashBytes)
	return
}

func (h HashType) Equal(hash HashType) bool {
	return h.md5 == hash.md5
}

func (h HashType) Bytes() []byte {
	return h.md5[:]
}

func (h HashType) String() string {
	return hex.EncodeToString(h.Bytes())
}

func (h HashType) Len() int {
	return len(h.md5)
}

func (h HashType) IsValid() bool {
	var zero HashType
	return h != zero
}
