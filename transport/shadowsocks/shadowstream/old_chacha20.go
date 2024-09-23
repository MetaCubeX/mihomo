package shadowstream

import (
	"crypto/cipher"

	"github.com/metacubex/chacha"
)

type chacha20key []byte

func (k chacha20key) IVSize() int {
	return chacha.NonceSize
}
func (k chacha20key) Encrypter(iv []byte) cipher.Stream {
	c, _ := chacha.NewChaCha20(iv, k)
	return c
}
func (k chacha20key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}
func ChaCha20(key []byte) (Cipher, error) {
	return chacha20key(key), nil
}
