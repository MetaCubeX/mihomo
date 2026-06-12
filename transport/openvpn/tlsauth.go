package openvpn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

type TLSAuth struct {
	signKey    []byte
	verifyKey  []byte
	newHash    func() hash.Hash
	digestSize int
}

func NewTLSAuth(staticKey []byte, auth string, keyDirection int, client bool) (*TLSAuth, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-auth static key length %d, expected %d", len(staticKey), staticKeySize)
	}
	if keyDirection != 0 && keyDirection != 1 {
		return nil, fmt.Errorf("unsupported tls-auth key-direction %d: only 0 and 1 are supported", keyDirection)
	}
	newHash, digestSize, err := tlsAuthHash(auth)
	if err != nil {
		return nil, err
	}

	key0 := staticKey[:keySlotSize]
	key1 := staticKey[keySlotSize:]
	sign := key0
	verify := key1
	if client {
		if keyDirection == 1 {
			sign = key1
			verify = key0
		}
	} else if keyDirection == 1 {
		sign = key0
		verify = key1
	}

	return &TLSAuth{
		signKey:    cloneBytes(sign[64 : 64+digestSize]),
		verifyKey:  cloneBytes(verify[64 : 64+digestSize]),
		newHash:    newHash,
		digestSize: digestSize,
	}, nil
}

func tlsAuthHash(auth string) (func() hash.Hash, int, error) {
	switch normalizeAuth(auth) {
	case AuthMD5:
		return md5.New, md5.Size, nil
	case AuthSHA1:
		return sha1.New, sha1.Size, nil
	case AuthSHA256:
		return sha256.New, sha256.Size, nil
	case AuthSHA384:
		return sha512.New384, sha512.Size384, nil
	case AuthSHA512:
		return sha512.New, sha512.Size, nil
	default:
		return nil, 0, fmt.Errorf("unsupported tls-auth digest %q", auth)
	}
}

func (a *TLSAuth) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != TLSCryptHeaderSize {
		return nil, fmt.Errorf("invalid tls-auth header length %d, expected %d", len(header), TLSCryptHeaderSize)
	}

	var pid [TLSCryptPIDSize]byte
	binary.BigEndian.PutUint32(pid[:4], packetID)
	binary.BigEndian.PutUint32(pid[4:], unixTime)
	tag := a.hmac(pid[:], header, plaintext)

	out := make([]byte, 0, len(header)+len(tag)+len(pid)+len(plaintext))
	out = append(out, header...)
	out = append(out, tag...)
	out = append(out, pid[:]...)
	out = append(out, plaintext...)
	return out, nil
}

func (a *TLSAuth) Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error) {
	if len(packet) < TLSCryptHeaderSize+a.digestSize+TLSCryptPIDSize+1 {
		return nil, 0, 0, nil, errors.New("tls-auth packet too short")
	}

	header = cloneBytes(packet[:TLSCryptHeaderSize])
	tagStart := TLSCryptHeaderSize
	tagEnd := tagStart + a.digestSize
	pidEnd := tagEnd + TLSCryptPIDSize
	tag := packet[tagStart:tagEnd]
	pid := packet[tagEnd:pidEnd]
	plaintext = packet[pidEnd:]

	tagCheck := a.verifyHMAC(pid, header, plaintext)
	if !hmac.Equal(tag, tagCheck) {
		return nil, 0, 0, nil, errors.New("tls-auth authentication failed")
	}

	packetID = binary.BigEndian.Uint32(pid[:4])
	unixTime = binary.BigEndian.Uint32(pid[4:])
	return header, packetID, unixTime, cloneBytes(plaintext), nil
}

func (a *TLSAuth) hmac(parts ...[]byte) []byte {
	mac := hmac.New(a.newHash, a.signKey)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

func (a *TLSAuth) verifyHMAC(parts ...[]byte) []byte {
	mac := hmac.New(a.newHash, a.verifyKey)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}
