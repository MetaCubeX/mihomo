package generator

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"

	"filippo.io/edwards25519"
)

const X25519KeySize = 32

func GenX25519PrivateKey() (*ecdh.PrivateKey, error) {
	var privateKey [X25519KeySize]byte
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, err
	}

	// Avoid generating equivalent X25519 private keys
	// https://github.com/XTLS/Xray-core/pull/1747
	//
	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	return ecdh.X25519().NewPrivateKey(privateKey[:])
}

// GenerateSudokuMasterKey generates a random master private key (scalar) and its public key (point)
func GenerateSudokuMasterKey() (*edwards25519.Scalar, *edwards25519.Point, error) {
	// 1. Generate random scalar x (32 bytes)
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}

	x, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		return nil, nil, err
	}

	// 2. Calculate Public Key P = x * G
	P := new(edwards25519.Point).ScalarBaseMult(x)

	return x, P, nil
}

// SplitSudokuPrivateKey takes a master private key x and returns a new random split key (r, k)
// such that x = r + k (mod L).
// Returns hex encoded string of r || k (64 bytes)
func SplitSudokuPrivateKey(x *edwards25519.Scalar) (string, error) {
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

// EncodeSudokuPoint returns the hex string of the compressed point
func EncodeSudokuPoint(p *edwards25519.Point) string {
	return hex.EncodeToString(p.Bytes())
}

// EncodeSudokuScalar returns the hex string of the scalar
func EncodeSudokuScalar(s *edwards25519.Scalar) string {
	return hex.EncodeToString(s.Bytes())
}
