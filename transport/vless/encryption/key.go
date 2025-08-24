package encryption

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/metacubex/blake3"
	"github.com/metacubex/utls/mlkem"
)

const MLKEM768SeedLength = mlkem.SeedSize
const MLKEM768ClientLength = mlkem.EncapsulationKeySize768
const X25519PasswordSize = 32
const X25519PrivateKeySize = 32

func GenMLKEM768(seedStr string) (seedBase64, clientBase64, hash32Base64 string, err error) {
	var seed [MLKEM768SeedLength]byte
	if len(seedStr) > 0 {
		s, _ := base64.RawURLEncoding.DecodeString(seedStr)
		if len(s) != MLKEM768SeedLength {
			err = fmt.Errorf("invalid length of ML-KEM-768 seed: %s", seedStr)
			return
		}
		seed = [MLKEM768SeedLength]byte(s)
	} else {
		_, err = rand.Read(seed[:])
		if err != nil {
			return
		}
	}

	key, _ := mlkem.NewDecapsulationKey768(seed[:])
	client := key.EncapsulationKey().Bytes()
	hash32 := blake3.Sum256(client)
	seedBase64 = base64.RawURLEncoding.EncodeToString(seed[:])
	clientBase64 = base64.RawURLEncoding.EncodeToString(client)
	hash32Base64 = base64.RawURLEncoding.EncodeToString(hash32[:])
	return
}

func GenX25519(privateKeyStr string) (privateKeyBase64, passwordBase64, hash32Base64 string, err error) {
	var privateKey [X25519PrivateKeySize]byte
	if len(privateKeyStr) > 0 {
		s, _ := base64.RawURLEncoding.DecodeString(privateKeyStr)
		if len(s) != X25519PrivateKeySize {
			err = fmt.Errorf("invalid length of X25519 private key: %s", privateKeyStr)
			return
		}
		privateKey = [X25519PrivateKeySize]byte(s)
	} else {
		_, err = rand.Read(privateKey[:])
		if err != nil {
			return
		}
	}

	// Avoid generating equivalent X25519 private keys
	// https://github.com/XTLS/Xray-core/pull/1747
	//
	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	password := key.PublicKey().Bytes()
	hash32 := blake3.Sum256(password)
	privateKeyBase64 = base64.RawURLEncoding.EncodeToString(privateKey[:])
	passwordBase64 = base64.RawURLEncoding.EncodeToString(password)
	hash32Base64 = base64.RawURLEncoding.EncodeToString(hash32[:])
	return
}
