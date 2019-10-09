package snell

import (
	"crypto/cipher"

	"golang.org/x/crypto/argon2"
)

type snellCipher struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (sc *snellCipher) KeySize() int  { return 32 }
func (sc *snellCipher) SaltSize() int { return 16 }
func (sc *snellCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	return sc.makeAEAD(argon2.IDKey(sc.psk, salt, 3, 8, 1, uint32(sc.KeySize())))
}
func (sc *snellCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	return sc.makeAEAD(argon2.IDKey(sc.psk, salt, 3, 8, 1, uint32(sc.KeySize())))
}
