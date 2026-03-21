package sudoku

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku/crypto"
)

const kipHandshakeSkew = 60 * time.Second

func kipHandshakeClient(rc *crypto.RecordConn, seed string, userHash [kipHelloUserHashSize]byte, feats uint32) (uint32, error) {
	if rc == nil {
		return 0, fmt.Errorf("nil conn")
	}

	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return 0, fmt.Errorf("ecdh generate failed: %w", err)
	}

	var nonce [kipHelloNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return 0, fmt.Errorf("nonce generate failed: %w", err)
	}

	var clientPub [kipHelloPubSize]byte
	copy(clientPub[:], ephemeral.PublicKey().Bytes())

	ch := &KIPClientHello{
		Timestamp: time.Now(),
		UserHash:  userHash,
		Nonce:     nonce,
		ClientPub: clientPub,
		Features:  feats,
	}
	if err := WriteKIPMessage(rc, KIPTypeClientHello, ch.EncodePayload()); err != nil {
		return 0, fmt.Errorf("write client hello failed: %w", err)
	}

	msg, err := ReadKIPMessage(rc)
	if err != nil {
		return 0, fmt.Errorf("read server hello failed: %w", err)
	}
	if msg.Type != KIPTypeServerHello {
		return 0, fmt.Errorf("unexpected handshake message: %d", msg.Type)
	}
	sh, err := DecodeKIPServerHelloPayload(msg.Payload)
	if err != nil {
		return 0, fmt.Errorf("decode server hello failed: %w", err)
	}
	if sh.Nonce != nonce {
		return 0, fmt.Errorf("handshake nonce mismatch")
	}

	shared, err := x25519SharedSecret(ephemeral, sh.ServerPub[:])
	if err != nil {
		return 0, fmt.Errorf("ecdh failed: %w", err)
	}
	sessC2S, sessS2C, err := deriveSessionDirectionalBases(seed, shared, nonce)
	if err != nil {
		return 0, fmt.Errorf("derive session keys failed: %w", err)
	}
	if err := rc.Rekey(sessC2S, sessS2C); err != nil {
		return 0, fmt.Errorf("rekey failed: %w", err)
	}

	return sh.SelectedFeats, nil
}
