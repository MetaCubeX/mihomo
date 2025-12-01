package generator

import (
	"crypto/ecdh"
	"crypto/rand"
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
