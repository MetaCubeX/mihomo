package singsnell

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/argon2"
)

// Surge 6.7.0 (11520): FUN_1000123d0: AEAD keys are derived with these Argon2id parameters.
func DeriveKey(psk []byte, salt []byte) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]
}

func NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Surge 6.7.0 (11520): FUN_100012944: nonce is u64le(counter) || 0x00000000.
func IncreaseNonce(nonce []byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			return
		}
	}
}
