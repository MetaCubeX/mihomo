package openvpn

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

const (
	TLSAuthPIDSize = 4 + 4
	// tlsAuthHMACKeyOffset is where the HMAC key material starts inside a 128-byte
	// key slot: OpenVPN's struct key is 64 bytes of cipher key followed by 64 bytes
	// of HMAC key, and --tls-auth uses the first digest-size bytes of the HMAC half.
	tlsAuthHMACKeyOffset = 64
)

type TLSAuth struct {
	newHash        func() hash.Hash
	tagSize        int
	encryptHMACKey []byte
	decryptHMACKey []byte
}

// NewTLSAuth builds the --tls-auth control channel wrapper. authName selects the
// HMAC digest exactly as --auth does on the OpenVPN side (init.c sets
// tls_auth_key_type.digest to the --auth name): the tag length and the amount
// of key material taken from the static key both follow that digest, so a peer
// running "auth SHA256" or "auth SHA512" sees the tag size it expects.
func NewTLSAuth(staticKey []byte, keyDirection string, authName string) (*TLSAuth, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-auth static key length %d, expected %d", len(staticKey), staticKeySize)
	}
	if keyDirection != "0" && keyDirection != "1" && keyDirection != "" {
		return nil, fmt.Errorf("invalid tls-auth key-direction %q, expected '0', '1', or ''", keyDirection)
	}
	newHash, tagSize, err := newDataChannelAuth(normalizeAuth(authName))
	if err != nil {
		return nil, fmt.Errorf("tls-auth: %w", err)
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
		newHash:        newHash,
		tagSize:        tagSize,
		encryptHMACKey: cloneBytes(encrypt[tlsAuthHMACKeyOffset : tlsAuthHMACKeyOffset+tagSize]),
		decryptHMACKey: cloneBytes(decrypt[tlsAuthHMACKeyOffset : tlsAuthHMACKeyOffset+tagSize]),
	}, nil
}

// TagSize is the length of the HMAC tag that follows the packet header.
func (a *TLSAuth) TagSize() int {
	return a.tagSize
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
	if len(packet) < TLSCryptHeaderSize+a.tagSize+TLSAuthPIDSize+1 {
		return nil, 0, 0, nil, errors.New("tls-auth packet too short")
	}

	headerEnd := TLSCryptHeaderSize
	tagEnd := headerEnd + a.tagSize
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
	mac := hmac.New(a.newHash, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}
