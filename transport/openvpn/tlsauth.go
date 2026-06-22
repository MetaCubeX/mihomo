package openvpn

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

type TLSAuth struct {
	encryptHMACKey []byte
	decryptHMACKey []byte
	newHash        func() hash.Hash
	tagSize        int
}

const tlsAuthHMACKeySize = 64

func NewTLSAuth(staticKey []byte, keyDirection int, authName string) (*TLSAuth, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-auth static key length %d, expected %d", len(staticKey), staticKeySize)
	}
	newHash, tagSize, err := newDataChannelAuth(authName)
	if err != nil {
		return nil, err
	}
	if tagSize > tlsAuthHMACKeySize {
		return nil, fmt.Errorf("unsupported tls-auth HMAC size %d", tagSize)
	}

	key0 := staticKey[64 : 64+tlsAuthHMACKeySize]
	key1 := staticKey[keySlotSize+64 : keySlotSize+64+tlsAuthHMACKeySize]
	encrypt, decrypt := key0, key0
	switch keyDirection {
	case KeyDirectionBidirectional:
	case KeyDirectionNormal:
		encrypt, decrypt = key0, key1
	case KeyDirectionInverse:
		encrypt, decrypt = key1, key0
	default:
		return nil, fmt.Errorf("unsupported openvpn key-direction %d", keyDirection)
	}

	return &TLSAuth{
		encryptHMACKey: cloneBytes(encrypt[:tagSize]),
		decryptHMACKey: cloneBytes(decrypt[:tagSize]),
		newHash:        newHash,
		tagSize:        tagSize,
	}, nil
}

func (a *TLSAuth) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != controlHeaderSize {
		return nil, fmt.Errorf("invalid tls-auth header length %d, expected %d", len(header), controlHeaderSize)
	}
	var pid [ControlPacketIDSize]byte
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
	if len(packet) < controlHeaderSize+a.tagSize+ControlPacketIDSize+1 {
		return nil, 0, 0, nil, errors.New("tls-auth packet too short")
	}
	header = cloneBytes(packet[:controlHeaderSize])
	tag := packet[controlHeaderSize : controlHeaderSize+a.tagSize]
	pidStart := controlHeaderSize + a.tagSize
	pidEnd := pidStart + ControlPacketIDSize
	pid := packet[pidStart:pidEnd]
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
