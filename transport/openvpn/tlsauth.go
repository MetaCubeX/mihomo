package openvpn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	TLSAuthPIDSize = 4 + 4
	TLSAuthTagSize = sha1.Size
	tlsAuthKeySize = sha1.Size
)

type TLSAuth struct {
	encryptHMACKey []byte
	decryptHMACKey []byte
}

func NewTLSAuth(staticKey []byte, keyDirection string) (*TLSAuth, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-auth static key length %d, expected %d", len(staticKey), staticKeySize)
	}
	if keyDirection != "0" && keyDirection != "1" && keyDirection != "" {
		return nil, fmt.Errorf("invalid tls-auth key-direction %q, expected '0', '1', or ''", keyDirection)
	}

	key0 := staticKey[:keySlotSize]
	key1 := staticKey[keySlotSize:]

	var encrypt, decrypt []byte
	if keyDirection == "1" {
		encrypt = key1
		decrypt = key0
	} else if keyDirection == "0" {
		encrypt = key0
		decrypt = key1
	} else {
		encrypt = key0
		decrypt = key0
	}

	return &TLSAuth{
		encryptHMACKey: cloneBytes(encrypt[64 : 64+tlsAuthKeySize]),
		decryptHMACKey: cloneBytes(decrypt[64 : 64+tlsAuthKeySize]),
	}, nil
}

func (a *TLSAuth) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != TLSCryptHeaderSize {
		return nil, fmt.Errorf("invalid tls-auth header length %d, expected %d", len(header), TLSCryptHeaderSize)
	}

	var pid [TLSAuthPIDSize]byte
	binary.BigEndian.PutUint32(pid[:4], packetID)
	binary.BigEndian.PutUint32(pid[4:], unixTime)
	tag := a.hmac(a.encryptHMACKey, pid[:], header, plaintext)

	out := make([]byte, 0, len(header)+len(tag)+len(pid)+len(plaintext))
	out = append(out, header...)
	out = append(out, tag...)
	out = append(out, pid[:]...)
	out = append(out, plaintext...)
	return out, nil
}

func (a *TLSAuth) Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error) {
	if len(packet) < TLSCryptHeaderSize+TLSAuthTagSize+TLSAuthPIDSize+1 {
		return nil, 0, 0, nil, errors.New("tls-auth packet too short")
	}

	headerEnd := TLSCryptHeaderSize
	tagEnd := headerEnd + TLSAuthTagSize
	pidEnd := tagEnd + TLSAuthPIDSize
	header = cloneBytes(packet[:headerEnd])
	tag := packet[headerEnd:tagEnd]
	pid := packet[tagEnd:pidEnd]
	plaintext = cloneBytes(packet[pidEnd:])

	tagCheck := a.hmac(a.decryptHMACKey, pid, header, plaintext)
	if !hmac.Equal(tag, tagCheck) {
		return nil, 0, 0, nil, errors.New("tls-auth authentication failed")
	}

	packetID = binary.BigEndian.Uint32(pid[:4])
	unixTime = binary.BigEndian.Uint32(pid[4:])
	return header, packetID, unixTime, plaintext, nil
}

func (a *TLSAuth) hmac(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha1.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}
