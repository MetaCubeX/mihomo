package mkcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

// NewAEADAESGCMBasedOnSeed derives an AES-128-GCM AEAD from a seed string,
// using the first 16 bytes of SHA-256(seed) as the key. This matches Xray's
// mKCP "seed" security exactly so encrypted packets interoperate.
func NewAEADAESGCMBasedOnSeed(seed string) cipher.AEAD {
	hashedSeed := sha256.Sum256([]byte(seed))
	block, err := aes.NewCipher(hashedSeed[:16])
	if err != nil {
		// aes.NewCipher only fails on invalid key sizes; 16 bytes is always valid.
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}
