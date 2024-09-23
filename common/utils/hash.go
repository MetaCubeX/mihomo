package utils

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
)

// HashType warps hash array inside struct
// someday can change to other hash algorithm simply
type HashType struct {
	md5 [md5.Size]byte // MD5
}

func MakeHash(data []byte) HashType {
	return HashType{md5.Sum(data)}
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

func (h HashType) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

func (h *HashType) UnmarshalText(data []byte) error {
	if hex.DecodedLen(len(data)) != md5.Size {
		return errors.New("invalid hash length")
	}
	_, err := hex.Decode(h.md5[:], data)
	return err
}

func (h HashType) MarshalBinary() ([]byte, error) {
	return h.md5[:], nil
}

func (h *HashType) UnmarshalBinary(data []byte) error {
	if len(data) != md5.Size {
		return errors.New("invalid hash length")
	}
	copy(h.md5[:], data)
	return nil
}

func (h HashType) Len() int {
	return len(h.md5)
}

func (h HashType) IsValid() bool {
	var zero HashType
	return h != zero
}
