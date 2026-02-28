package sudoku

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	kipMagic = "kip"

	KIPTypeClientHello byte = 0x01
	KIPTypeServerHello byte = 0x02

	KIPTypeOpenTCP   byte = 0x10
	KIPTypeStartMux  byte = 0x11
	KIPTypeStartUoT  byte = 0x12
	KIPTypeKeepAlive byte = 0x14
)

// KIP feature bits are advisory capability flags negotiated during the handshake.
// They represent control-plane message families.
const (
	KIPFeatOpenTCP   uint32 = 1 << 0
	KIPFeatMux       uint32 = 1 << 1
	KIPFeatUoT       uint32 = 1 << 2
	KIPFeatKeepAlive uint32 = 1 << 4

	KIPFeatAll = KIPFeatOpenTCP | KIPFeatMux | KIPFeatUoT | KIPFeatKeepAlive
)

const (
	kipHelloUserHashSize = 8
	kipHelloNonceSize    = 16
	kipHelloPubSize      = 32
	kipMaxPayload        = 64 * 1024
)

var errKIP = errors.New("kip protocol error")

type KIPMessage struct {
	Type    byte
	Payload []byte
}

func WriteKIPMessage(w io.Writer, typ byte, payload []byte) error {
	if w == nil {
		return fmt.Errorf("%w: nil writer", errKIP)
	}
	if len(payload) > kipMaxPayload {
		return fmt.Errorf("%w: payload too large: %d", errKIP, len(payload))
	}

	var hdr [3 + 1 + 2]byte
	copy(hdr[:3], []byte(kipMagic))
	hdr[3] = typ
	binary.BigEndian.PutUint16(hdr[4:], uint16(len(payload)))

	if err := writeFull(w, hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	return writeFull(w, payload)
}

func ReadKIPMessage(r io.Reader) (*KIPMessage, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", errKIP)
	}
	var hdr [3 + 1 + 2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if string(hdr[:3]) != kipMagic {
		return nil, fmt.Errorf("%w: bad magic", errKIP)
	}
	typ := hdr[3]
	n := int(binary.BigEndian.Uint16(hdr[4:]))
	if n < 0 || n > kipMaxPayload {
		return nil, fmt.Errorf("%w: invalid payload length: %d", errKIP, n)
	}
	var payload []byte
	if n > 0 {
		payload = make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &KIPMessage{Type: typ, Payload: payload}, nil
}

type KIPClientHello struct {
	Timestamp time.Time
	UserHash  [kipHelloUserHashSize]byte
	Nonce     [kipHelloNonceSize]byte
	ClientPub [kipHelloPubSize]byte
	Features  uint32
}

type KIPServerHello struct {
	Nonce         [kipHelloNonceSize]byte
	ServerPub     [kipHelloPubSize]byte
	SelectedFeats uint32
}

func kipUserHashFromKey(psk string) [kipHelloUserHashSize]byte {
	var out [kipHelloUserHashSize]byte
	psk = strings.TrimSpace(psk)
	if psk == "" {
		return out
	}

	// Align with upstream: when the client carries private key material (or even just a public key),
	// prefer hashing the raw hex bytes so different split/master keys can be distinguished.
	if keyBytes, err := hex.DecodeString(psk); err == nil && len(keyBytes) > 0 {
		sum := sha256.Sum256(keyBytes)
		copy(out[:], sum[:kipHelloUserHashSize])
		return out
	}

	sum := sha256.Sum256([]byte(psk))
	copy(out[:], sum[:kipHelloUserHashSize])
	return out
}

func KIPUserHashHexFromKey(psk string) string {
	uh := kipUserHashFromKey(psk)
	return hex.EncodeToString(uh[:])
}

func (m *KIPClientHello) EncodePayload() []byte {
	var b bytes.Buffer
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(m.Timestamp.Unix()))
	b.Write(tmp[:])
	b.Write(m.UserHash[:])
	b.Write(m.Nonce[:])
	b.Write(m.ClientPub[:])
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], m.Features)
	b.Write(f[:])
	return b.Bytes()
}

func DecodeKIPClientHelloPayload(payload []byte) (*KIPClientHello, error) {
	const minLen = 8 + kipHelloUserHashSize + kipHelloNonceSize + kipHelloPubSize + 4
	if len(payload) < minLen {
		return nil, fmt.Errorf("%w: client hello too short", errKIP)
	}
	var h KIPClientHello
	ts := int64(binary.BigEndian.Uint64(payload[:8]))
	h.Timestamp = time.Unix(ts, 0)
	off := 8
	copy(h.UserHash[:], payload[off:off+kipHelloUserHashSize])
	off += kipHelloUserHashSize
	copy(h.Nonce[:], payload[off:off+kipHelloNonceSize])
	off += kipHelloNonceSize
	copy(h.ClientPub[:], payload[off:off+kipHelloPubSize])
	off += kipHelloPubSize
	h.Features = binary.BigEndian.Uint32(payload[off : off+4])
	return &h, nil
}

func (m *KIPServerHello) EncodePayload() []byte {
	var b bytes.Buffer
	b.Write(m.Nonce[:])
	b.Write(m.ServerPub[:])
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], m.SelectedFeats)
	b.Write(f[:])
	return b.Bytes()
}

func DecodeKIPServerHelloPayload(payload []byte) (*KIPServerHello, error) {
	const want = kipHelloNonceSize + kipHelloPubSize + 4
	if len(payload) != want {
		return nil, fmt.Errorf("%w: server hello bad len: %d", errKIP, len(payload))
	}
	var h KIPServerHello
	off := 0
	copy(h.Nonce[:], payload[off:off+kipHelloNonceSize])
	off += kipHelloNonceSize
	copy(h.ServerPub[:], payload[off:off+kipHelloPubSize])
	off += kipHelloPubSize
	h.SelectedFeats = binary.BigEndian.Uint32(payload[off : off+4])
	return &h, nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
