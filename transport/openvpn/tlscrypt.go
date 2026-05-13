package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	TLSCryptHeaderSize = 1 + 8
	TLSCryptPIDSize    = 4 + 4
	TLSCryptTagSize    = sha256.Size

	staticKeySize = 256
	keySlotSize   = 128
	cipherKeySize = 32
	hmacKeySize   = 32
)

type TLSCrypt struct {
	encryptCipherKey []byte
	encryptHMACKey   []byte
	decryptCipherKey []byte
	decryptHMACKey   []byte
}

func NewTLSCrypt(staticKey []byte, client bool) (*TLSCrypt, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-crypt static key length %d, expected %d", len(staticKey), staticKeySize)
	}

	key0 := staticKey[:keySlotSize]
	key1 := staticKey[keySlotSize:]

	encrypt := key0
	decrypt := key1
	if client {
		encrypt = key1
		decrypt = key0
	}

	return &TLSCrypt{
		encryptCipherKey: cloneBytes(encrypt[:cipherKeySize]),
		encryptHMACKey:   cloneBytes(encrypt[64 : 64+hmacKeySize]),
		decryptCipherKey: cloneBytes(decrypt[:cipherKeySize]),
		decryptHMACKey:   cloneBytes(decrypt[64 : 64+hmacKeySize]),
	}, nil
}

func (c *TLSCrypt) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != TLSCryptHeaderSize {
		return nil, fmt.Errorf("invalid tls-crypt header length %d, expected %d", len(header), TLSCryptHeaderSize)
	}

	ad := make([]byte, 0, len(header)+TLSCryptPIDSize)
	ad = append(ad, header...)
	var pid [TLSCryptPIDSize]byte
	binary.BigEndian.PutUint32(pid[:4], packetID)
	binary.BigEndian.PutUint32(pid[4:], unixTime)
	ad = append(ad, pid[:]...)

	tag := c.hmac(c.encryptHMACKey, ad, plaintext)
	ciphertext, err := aes256ctr(c.encryptCipherKey, tag[:aes.BlockSize], plaintext)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(ad)+len(tag)+len(ciphertext))
	out = append(out, ad...)
	out = append(out, tag...)
	out = append(out, ciphertext...)
	return out, nil
}

func (c *TLSCrypt) Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error) {
	if len(packet) < TLSCryptHeaderSize+TLSCryptPIDSize+TLSCryptTagSize {
		return nil, 0, 0, nil, errors.New("tls-crypt packet too short")
	}

	header = cloneBytes(packet[:TLSCryptHeaderSize])
	adEnd := TLSCryptHeaderSize + TLSCryptPIDSize
	tagEnd := adEnd + TLSCryptTagSize
	ad := packet[:adEnd]
	tag := packet[adEnd:tagEnd]
	ciphertext := packet[tagEnd:]

	plaintext, err = aes256ctr(c.decryptCipherKey, tag[:aes.BlockSize], ciphertext)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	tagCheck := c.hmac(c.decryptHMACKey, ad, plaintext)
	if !hmac.Equal(tag, tagCheck) {
		return nil, 0, 0, nil, errors.New("tls-crypt authentication failed")
	}

	packetID = binary.BigEndian.Uint32(packet[TLSCryptHeaderSize : TLSCryptHeaderSize+4])
	unixTime = binary.BigEndian.Uint32(packet[TLSCryptHeaderSize+4 : adEnd])
	return header, packetID, unixTime, plaintext, nil
}

func (c *TLSCrypt) hmac(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

func aes256ctr(key, iv, in []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := cloneBytes(in)
	cipher.NewCTR(block, iv).XORKeyStream(out, out)
	return out, nil
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
