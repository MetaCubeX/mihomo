package openvpn

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// TLSCryptV2 implements the OpenVPN tls-crypt-v2 control channel wrapper.
//
// In tls-crypt-v2 (OpenVPN 2.5+), the client and server each have their own
// 256-byte key. The client wraps outgoing packets with the client key, and
// the server wraps outgoing packets with the server key. This is different
// from tls-crypt v1, where both sides share the same 256-byte static key
// and use opposite key slots.
//
// The client key is delivered to the server during the initial handshake
// as a wrapped blob. After that, both sides use the same wrap/unwrap logic
// as v1 but with independent keys.
type TLSCryptV2 struct {
	// encryptKey is the key used to wrap outgoing packets.
	// For the client, this is the client key; for the server, the server key.
	encryptKey []byte // 256 bytes
	// decryptKey is the key used to unwrap incoming packets.
	// For the client, this is the server key; for the server, the client key.
	decryptKey []byte // 256 bytes
}

// tlsCryptV2ClientKeySize is the total size of a tls-crypt-v2 client key.
const tlsCryptV2ClientKeySize = 256

// NewTLSCryptV2 creates a tls-crypt-v2 wrapper from a client key and server key.
// Both keys must be exactly 256 bytes.
//
// For a client:
//   clientKey is the client's own key (used for encryption).
//   serverKey is the server's key (used for decryption).
//
// For a server:
//   clientKey is the client's key (used for decryption).
//   serverKey is the server's own key (used for encryption).
func NewTLSCryptV2(clientKey, serverKey []byte, isClient bool) (*TLSCryptV2, error) {
	if len(clientKey) != tlsCryptV2ClientKeySize {
		return nil, fmt.Errorf("invalid tls-crypt-v2 client key length %d, expected %d", len(clientKey), tlsCryptV2ClientKeySize)
	}
	if len(serverKey) != tlsCryptV2ClientKeySize {
		return nil, fmt.Errorf("invalid tls-crypt-v2 server key length %d, expected %d", len(serverKey), tlsCryptV2ClientKeySize)
	}
	c := &TLSCryptV2{
		encryptKey: cloneBytes(clientKey),
		decryptKey: cloneBytes(serverKey),
	}
	if !isClient {
		// Server: encrypt with server key, decrypt with client key.
		c.encryptKey = cloneBytes(serverKey)
		c.decryptKey = cloneBytes(clientKey)
	}
	return c, nil
}

// Wrap encrypts a control packet using tls-crypt-v2.
// The format is identical to v1: header + packet_id + unix_time + HMAC tag + ciphertext.
func (c *TLSCryptV2) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != TLSCryptHeaderSize {
		return nil, fmt.Errorf("invalid tls-crypt-v2 header length %d, expected %d", len(header), TLSCryptHeaderSize)
	}

	ad := make([]byte, 0, len(header)+TLSCryptPIDSize)
	ad = append(ad, header...)
	var pid [TLSCryptPIDSize]byte
	binary.BigEndian.PutUint32(pid[:4], packetID)
	binary.BigEndian.PutUint32(pid[4:], unixTime)
	ad = append(ad, pid[:]...)

	cipherKey := c.encryptKey[:cipherKeySize]
	hmacKey := c.encryptKey[64 : 64+hmacKeySize]

	tag := tlsCryptV2HMAC(hmacKey, ad, plaintext)
	ciphertext, err := aes256ctr(cipherKey, tag[:aes.BlockSize], plaintext)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(ad)+len(tag)+len(ciphertext))
	out = append(out, ad...)
	out = append(out, tag...)
	out = append(out, ciphertext...)
	return out, nil
}

// Unwrap decrypts a control packet using tls-crypt-v2.
func (c *TLSCryptV2) Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error) {
	if len(packet) < TLSCryptHeaderSize+TLSCryptPIDSize+TLSCryptTagSize {
		return nil, 0, 0, nil, errors.New("tls-crypt-v2 packet too short")
	}

	header = cloneBytes(packet[:TLSCryptHeaderSize])
	adEnd := TLSCryptHeaderSize + TLSCryptPIDSize
	tagEnd := adEnd + TLSCryptTagSize
	ad := packet[:adEnd]
	tag := packet[adEnd:tagEnd]
	ciphertext := packet[tagEnd:]

	cipherKey := c.decryptKey[:cipherKeySize]
	hmacKey := c.decryptKey[64 : 64+hmacKeySize]

	plaintext, err = aes256ctr(cipherKey, tag[:aes.BlockSize], ciphertext)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	tagCheck := tlsCryptV2HMAC(hmacKey, ad, plaintext)
	if !hmac.Equal(tag, tagCheck) {
		return nil, 0, 0, nil, errors.New("tls-crypt-v2 authentication failed")
	}

	packetID = binary.BigEndian.Uint32(packet[TLSCryptHeaderSize : TLSCryptHeaderSize+4])
	unixTime = binary.BigEndian.Uint32(packet[TLSCryptHeaderSize+4 : adEnd])
	return header, packetID, unixTime, plaintext, nil
}

// tlsCryptV2HMAC computes HMAC-SHA256 over all provided byte slices.
func tlsCryptV2HMAC(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

// DecodeTLSCryptV2ClientKey decodes a tls-crypt-v2 client key from a PEM block.
// The PEM type must be "OpenVPN tls-crypt-v2 client key".
// The raw key is 256 bytes of binary data (base64-encoded in PEM).
func DecodeTLSCryptV2ClientKey(block []byte) ([]byte, error) {
	return decodeStaticKeyWithType(block, "OpenVPN tls-crypt-v2 client key")
}

// DecodeTLSCryptV2ServerKey decodes a tls-crypt-v2 server key from a PEM block.
// The PEM type must be "OpenVPN tls-crypt-v2 server key".
func DecodeTLSCryptV2ServerKey(block []byte) ([]byte, error) {
	return decodeStaticKeyWithType(block, "OpenVPN tls-crypt-v2 server key")
}
