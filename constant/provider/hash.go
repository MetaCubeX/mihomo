package provider

import (
	"bytes"
	"crypto/md5"
)

type HashType [md5.Size]byte // MD5

func MakeHash(data []byte) HashType {
	return md5.Sum(data)
}

func (h HashType) Equal(hash HashType) bool {
	return h == hash
}

func (h HashType) EqualBytes(hashBytes []byte) bool {
	return bytes.Equal(hashBytes, h[:])
}

func (h HashType) Bytes() []byte {
	return h[:]
}

func (h HashType) IsValid() bool {
	var zero HashType
	return h != zero
}
