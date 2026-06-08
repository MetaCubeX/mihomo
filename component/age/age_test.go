package age_test

import (
	"testing"

	"github.com/metacubex/mihomo/component/age"
)

func TestAge(t *testing.T) {
	testCases := []struct {
		name string
		gen  func() (string, string, error)
	}{
		{"X25519", age.GenX25519KeyPair},
		{"MLKEM768X25519", age.GenHybridKeyPair},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			secretKey, publicKey, err := tc.gen()
			if err != nil {
				t.Fatal(err)
			}
			t.Log(secretKey, publicKey)
			publicKeys, err := age.ToPublicKeys(secretKey)
			if err != nil {
				t.Fatal(err)
			}
			if len(publicKeys) != 1 {
				t.Fatal("public keys length is not equal to 1")
			}
			if publicKeys[0] != publicKey {
				t.Fatal("public key is not equal")
			}
			rawData := []byte("hello world")
			encryptData, err := age.EncryptBytes(rawData, publicKey)
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(encryptData))
			decryptData, err := age.DecryptBytes(encryptData, secretKey)
			if err != nil {
				t.Fatal(err)
			}
			if string(decryptData) != string(rawData) {
				t.Fatal("decrypt data is not equal to raw data")
			}
		})
	}
}
