package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

type AEADConn struct {
	net.Conn
	aead      cipher.AEAD
	readBuf   bytes.Buffer
	nonceSize int
}

func NewAEADConn(c net.Conn, key string, method string) (*AEADConn, error) {
	if method == "none" {
		return &AEADConn{Conn: c, aead: nil}, nil
	}

	h := sha256.New()
	h.Write([]byte(key))
	keyBytes := h.Sum(nil)

	var aead cipher.AEAD
	var err error

	switch method {
	case "aes-128-gcm":
		block, _ := aes.NewCipher(keyBytes[:16])
		aead, err = cipher.NewGCM(block)
	case "chacha20-poly1305":
		aead, err = chacha20poly1305.New(keyBytes)
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", method)
	}
	if err != nil {
		return nil, err
	}

	return &AEADConn{
		Conn:      c,
		aead:      aead,
		nonceSize: aead.NonceSize(),
	}, nil
}

func (cc *AEADConn) Write(p []byte) (int, error) {
	if cc.aead == nil {
		return cc.Conn.Write(p)
	}

	maxPayload := 65535 - cc.nonceSize - cc.aead.Overhead()
	totalWritten := 0
	var frameBuf bytes.Buffer
	header := make([]byte, 2)
	nonce := make([]byte, cc.nonceSize)

	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPayload {
			chunkSize = maxPayload
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return totalWritten, err
		}

		ciphertext := cc.aead.Seal(nil, nonce, chunk, nil)
		frameLen := len(nonce) + len(ciphertext)
		binary.BigEndian.PutUint16(header, uint16(frameLen))

		frameBuf.Reset()
		frameBuf.Write(header)
		frameBuf.Write(nonce)
		frameBuf.Write(ciphertext)

		if _, err := cc.Conn.Write(frameBuf.Bytes()); err != nil {
			return totalWritten, err
		}
		totalWritten += chunkSize
	}
	return totalWritten, nil
}

func (cc *AEADConn) Read(p []byte) (int, error) {
	if cc.aead == nil {
		return cc.Conn.Read(p)
	}

	if cc.readBuf.Len() > 0 {
		return cc.readBuf.Read(p)
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(cc.Conn, header); err != nil {
		return 0, err
	}
	frameLen := int(binary.BigEndian.Uint16(header))

	body := make([]byte, frameLen)
	if _, err := io.ReadFull(cc.Conn, body); err != nil {
		return 0, err
	}

	if len(body) < cc.nonceSize {
		return 0, errors.New("frame too short")
	}
	nonce := body[:cc.nonceSize]
	ciphertext := body[cc.nonceSize:]

	plaintext, err := cc.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, errors.New("decryption failed")
	}

	cc.readBuf.Write(plaintext)
	return cc.readBuf.Read(p)
}
