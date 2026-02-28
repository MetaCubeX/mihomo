package sudoku

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func derivePSKDirectionalBases(psk string) (c2s, s2c []byte) {
	sum := sha256.Sum256([]byte(psk))
	c2sKey := make([]byte, 32)
	s2cKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, sum[:], []byte("sudoku-psk-c2s")), c2sKey); err != nil {
		panic("sudoku: hkdf expand failed")
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, sum[:], []byte("sudoku-psk-s2c")), s2cKey); err != nil {
		panic("sudoku: hkdf expand failed")
	}
	return c2sKey, s2cKey
}

func deriveSessionDirectionalBases(psk string, shared []byte, nonce [kipHelloNonceSize]byte) (c2s, s2c []byte, err error) {
	sum := sha256.Sum256([]byte(psk))
	ikm := make([]byte, 0, len(shared)+len(nonce))
	ikm = append(ikm, shared...)
	ikm = append(ikm, nonce[:]...)

	prk := hkdf.Extract(sha256.New, ikm, sum[:])

	c2sKey := make([]byte, 32)
	s2cKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("sudoku-session-c2s")), c2sKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf expand c2s: %w", err)
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("sudoku-session-s2c")), s2cKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf expand s2c: %w", err)
	}
	return c2sKey, s2cKey, nil
}

func x25519SharedSecret(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("nil priv")
	}
	curve := ecdh.X25519()
	pk, err := curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("parse peer pub: %w", err)
	}
	secret, err := priv.ECDH(pk)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	return secret, nil
}
