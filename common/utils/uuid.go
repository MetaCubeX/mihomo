package utils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"strings"

	"github.com/gofrs/uuid/v5"
)

// NewUUIDV3 returns a UUID based on the MD5 hash of the namespace UUID and name.
func NewUUIDV3(ns uuid.UUID, name string) (u uuid.UUID) {
	h := md5.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	copy(u[:], h.Sum(make([]byte, 0, md5.Size)))

	u.SetVersion(uuid.V3)
	u.SetVariant(uuid.VariantRFC9562)
	return u
}

// NewUUIDV4 returns a new version 4 UUID.
//
// Version 4 UUIDs contain 122 bits of random data.
func NewUUIDV4() (u uuid.UUID) {
	rand.Read(u[:])
	u.SetVersion(uuid.V4)
	u.SetVariant(uuid.VariantRFC9562)
	return u
}

// NewUUIDV5 returns a UUID based on SHA-1 hash of the namespace UUID and name.
func NewUUIDV5(ns uuid.UUID, name string) (u uuid.UUID) {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	copy(u[:], h.Sum(make([]byte, 0, sha1.Size)))

	u.SetVersion(uuid.V5)
	u.SetVariant(uuid.VariantRFC9562)
	return u
}

// UUIDMap https://github.com/XTLS/Xray-core/issues/158#issue-783294090
func UUIDMap(str string) uuid.UUID {
	u, err := uuid.FromString(str)
	if err != nil {
		return NewUUIDV5(uuid.Nil, str)
	}
	return u
}

// ParseGUID parses a canonical textual GUID, as in
// "00000000-0000-0000-0000-000000000000".
// The form is all that is accepted, not the other ones uuid.FromString takes,
// such as one without hyphens.
func ParseGUID(s string) (uuid.UUID, error) {
	u, err := uuid.FromString(s)
	if err != nil {
		return uuid.Nil, err
	}
	if u.String() != strings.ToLower(s) {
		return uuid.Nil, fmt.Errorf("invalid guid: %s, want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", s)
	}
	return u, nil
}
