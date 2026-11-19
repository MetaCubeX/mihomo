package generator

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

func GenShadowsocksPassword(bits int) (string, error) {
	if bits%8 != 0 {
		return "", errors.New("bits must be multiple of 8")
	}
	password := make([]byte, bits/8)
	if _, err := rand.Read(password); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(password), nil
}
