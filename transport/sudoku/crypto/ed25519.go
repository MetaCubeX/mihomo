package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// KeyPair holds the scalar private key and point public key
type KeyPair struct {
	Private *edwards25519.Scalar
	Public  *edwards25519.Point
}

// GenerateMasterKey generates a random master private key (scalar) and its public key (point)
func GenerateMasterKey() (*KeyPair, error) {
	// 1. Generate random scalar x (32 bytes)
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}

	x, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		return nil, err
	}

	// 2. Calculate Public Key P = x * G
	P := new(edwards25519.Point).ScalarBaseMult(x)

	return &KeyPair{Private: x, Public: P}, nil
}

// SplitPrivateKey takes a master private key x and returns a new random split key (r, k)
// such that x = r + k (mod L).
// Returns hex encoded string of r || k (64 bytes)
func SplitPrivateKey(x *edwards25519.Scalar) (string, error) {
	// 1. Generate random r (32 bytes)
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return "", err
	}
	r, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		return "", err
	}

	// 2. Calculate k = x - r (mod L)
	k := new(edwards25519.Scalar).Subtract(x, r)

	// 3. Encode r and k
	rBytes := r.Bytes()
	kBytes := k.Bytes()

	full := make([]byte, 64)
	copy(full[:32], rBytes)
	copy(full[32:], kBytes)

	return hex.EncodeToString(full), nil
}

// RecoverPublicKey takes a split private key (r, k) or a master private key (x)
// and returns the public key P.
// Input can be:
// - 32 bytes hex (Master Scalar x)
// - 64 bytes hex (Split Key r || k)
func RecoverPublicKey(keyHex string) (*edwards25519.Point, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	if len(keyBytes) == 32 {
		// Master Key x
		x, err := edwards25519.NewScalar().SetCanonicalBytes(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid scalar: %w", err)
		}
		return new(edwards25519.Point).ScalarBaseMult(x), nil

	} else if len(keyBytes) == 64 {
		// Split Key r || k
		rBytes := keyBytes[:32]
		kBytes := keyBytes[32:]

		r, err := edwards25519.NewScalar().SetCanonicalBytes(rBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid scalar r: %w", err)
		}
		k, err := edwards25519.NewScalar().SetCanonicalBytes(kBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid scalar k: %w", err)
		}

		// sum = r + k
		sum := new(edwards25519.Scalar).Add(r, k)

		// P = sum * G
		return new(edwards25519.Point).ScalarBaseMult(sum), nil
	}

	return nil, errors.New("invalid key length: must be 32 bytes (Master) or 64 bytes (Split)")
}

// EncodePoint returns the hex string of the compressed point
func EncodePoint(p *edwards25519.Point) string {
	return hex.EncodeToString(p.Bytes())
}

// EncodeScalar returns the hex string of the scalar
func EncodeScalar(s *edwards25519.Scalar) string {
	return hex.EncodeToString(s.Bytes())
}
