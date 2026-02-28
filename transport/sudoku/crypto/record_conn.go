package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeyUpdateAfterBytes controls automatic key rotation based on plaintext bytes.
// It is a package var (not config) to enable targeted tests with smaller thresholds.
var KeyUpdateAfterBytes int64 = 32 << 20 // 32 MiB

const (
	recordHeaderSize = 12 // epoch(uint32) + seq(uint64) - also used as nonce+AAD.
	maxFrameBodySize = 65535
)

type recordKeys struct {
	baseSend []byte
	baseRecv []byte
}

// RecordConn is a framed AEAD net.Conn with:
//   - deterministic per-record nonce (epoch+seq)
//   - per-direction key rotation (epoch), driven by plaintext byte counters
//   - replay/out-of-order protection within the connection (strict seq check)
//
// Wire format per record:
//   - uint16 bodyLen
//   - header[12] = epoch(uint32 BE) || seq(uint64 BE)  (plaintext)
//   - ciphertext = AEAD(header as nonce, plaintext, header as AAD)
type RecordConn struct {
	net.Conn
	method string

	writeMu sync.Mutex
	readMu  sync.Mutex

	keys recordKeys

	sendAEAD      cipher.AEAD
	sendAEADEpoch uint32

	recvAEAD      cipher.AEAD
	recvAEADEpoch uint32

	// Send direction state.
	sendEpoch uint32
	sendSeq   uint64
	sendBytes int64

	// Receive direction state.
	recvEpoch uint32
	recvSeq   uint64

	readBuf bytes.Buffer

	// writeFrame is a reusable buffer for [len||header||ciphertext] on the wire.
	// Guarded by writeMu.
	writeFrame []byte
}

func (c *RecordConn) CloseWrite() error {
	if c == nil {
		return nil
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *RecordConn) CloseRead() error {
	if c == nil {
		return nil
	}
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func NewRecordConn(conn net.Conn, method string, baseSend, baseRecv []byte) (*RecordConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	method = normalizeAEADMethod(method)
	if method != "none" {
		if err := validateBaseKey(baseSend); err != nil {
			return nil, fmt.Errorf("invalid send base key: %w", err)
		}
		if err := validateBaseKey(baseRecv); err != nil {
			return nil, fmt.Errorf("invalid recv base key: %w", err)
		}
	}
	rc := &RecordConn{Conn: conn, method: method}
	rc.keys = recordKeys{baseSend: cloneBytes(baseSend), baseRecv: cloneBytes(baseRecv)}
	return rc, nil
}

func (c *RecordConn) Rekey(baseSend, baseRecv []byte) error {
	if c == nil {
		return fmt.Errorf("nil conn")
	}
	if c.method != "none" {
		if err := validateBaseKey(baseSend); err != nil {
			return fmt.Errorf("invalid send base key: %w", err)
		}
		if err := validateBaseKey(baseRecv); err != nil {
			return fmt.Errorf("invalid recv base key: %w", err)
		}
	}

	c.writeMu.Lock()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	defer c.writeMu.Unlock()

	c.keys = recordKeys{baseSend: cloneBytes(baseSend), baseRecv: cloneBytes(baseRecv)}
	c.sendEpoch = 0
	c.sendSeq = 0
	c.sendBytes = 0
	c.recvEpoch = 0
	c.recvSeq = 0
	c.readBuf.Reset()

	c.sendAEAD = nil
	c.recvAEAD = nil
	c.sendAEADEpoch = 0
	c.recvAEADEpoch = 0
	return nil
}

func normalizeAEADMethod(method string) string {
	switch method {
	case "", "chacha20-poly1305":
		return "chacha20-poly1305"
	case "aes-128-gcm", "none":
		return method
	default:
		return method
	}
}

func validateBaseKey(b []byte) error {
	if len(b) < 32 {
		return fmt.Errorf("need at least 32 bytes, got %d", len(b))
	}
	return nil
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

func (c *RecordConn) newAEADFor(base []byte, epoch uint32) (cipher.AEAD, error) {
	if c.method == "none" {
		return nil, nil
	}
	key := deriveEpochKey(base, epoch, c.method)
	switch c.method {
	case "aes-128-gcm":
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if a.NonceSize() != recordHeaderSize {
			return nil, fmt.Errorf("unexpected gcm nonce size: %d", a.NonceSize())
		}
		return a, nil
	case "chacha20-poly1305":
		a, err := chacha20poly1305.New(key[:32])
		if err != nil {
			return nil, err
		}
		if a.NonceSize() != recordHeaderSize {
			return nil, fmt.Errorf("unexpected chacha nonce size: %d", a.NonceSize())
		}
		return a, nil
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", c.method)
	}
}

func deriveEpochKey(base []byte, epoch uint32, method string) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], epoch)
	mac := hmac.New(sha256.New, base)
	_, _ = mac.Write([]byte("sudoku-record:"))
	_, _ = mac.Write([]byte(method))
	_, _ = mac.Write(b[:])
	return mac.Sum(nil)
}

func (c *RecordConn) maybeBumpSendEpochLocked(addedPlain int) {
	if KeyUpdateAfterBytes <= 0 || c.method == "none" {
		return
	}
	c.sendBytes += int64(addedPlain)
	threshold := KeyUpdateAfterBytes * int64(c.sendEpoch+1)
	if c.sendBytes < threshold {
		return
	}
	c.sendEpoch++
	c.sendSeq = 0
}

func (c *RecordConn) Write(p []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if c.method == "none" {
		return c.Conn.Write(p)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		if c.sendAEAD == nil || c.sendAEADEpoch != c.sendEpoch {
			a, err := c.newAEADFor(c.keys.baseSend, c.sendEpoch)
			if err != nil {
				return total, err
			}
			c.sendAEAD = a
			c.sendAEADEpoch = c.sendEpoch
		}
		aead := c.sendAEAD

		maxPlain := maxFrameBodySize - recordHeaderSize - aead.Overhead()
		if maxPlain <= 0 {
			return total, errors.New("frame size too small")
		}
		n := len(p)
		if n > maxPlain {
			n = maxPlain
		}
		chunk := p[:n]
		p = p[n:]

		var header [recordHeaderSize]byte
		binary.BigEndian.PutUint32(header[:4], c.sendEpoch)
		binary.BigEndian.PutUint64(header[4:], c.sendSeq)
		c.sendSeq++

		cipherLen := n + aead.Overhead()
		bodyLen := recordHeaderSize + cipherLen
		frameLen := 2 + bodyLen
		if bodyLen > maxFrameBodySize {
			return total, errors.New("frame too large")
		}
		if cap(c.writeFrame) < frameLen {
			c.writeFrame = make([]byte, frameLen)
		}
		frame := c.writeFrame[:frameLen]
		binary.BigEndian.PutUint16(frame[:2], uint16(bodyLen))
		copy(frame[2:2+recordHeaderSize], header[:])

		dst := frame[2+recordHeaderSize : 2+recordHeaderSize : frameLen]
		_ = aead.Seal(dst[:0], header[:], chunk, header[:])

		if err := writeFull(c.Conn, frame); err != nil {
			return total, err
		}

		total += n
		c.maybeBumpSendEpochLocked(n)
	}
	return total, nil
}

func (c *RecordConn) Read(p []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if c.method == "none" {
		return c.Conn.Read(p)
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}
	bodyLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if bodyLen < recordHeaderSize {
		return 0, errors.New("frame too short")
	}
	if bodyLen > maxFrameBodySize {
		return 0, errors.New("frame too large")
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return 0, err
	}
	header := body[:recordHeaderSize]
	ciphertext := body[recordHeaderSize:]

	epoch := binary.BigEndian.Uint32(header[:4])
	seq := binary.BigEndian.Uint64(header[4:])

	if epoch < c.recvEpoch {
		return 0, fmt.Errorf("replayed epoch: got %d want >=%d", epoch, c.recvEpoch)
	}
	if epoch == c.recvEpoch && seq != c.recvSeq {
		return 0, fmt.Errorf("out of order: epoch=%d got=%d want=%d", epoch, seq, c.recvSeq)
	}
	if epoch > c.recvEpoch {
		const maxJump = 8
		if epoch-c.recvEpoch > maxJump {
			return 0, fmt.Errorf("epoch jump too large: got=%d want<=%d", epoch-c.recvEpoch, maxJump)
		}
		c.recvEpoch = epoch
		c.recvSeq = 0
		if seq != 0 {
			return 0, fmt.Errorf("out of order: epoch advanced to %d but seq=%d", epoch, seq)
		}
	}

	if c.recvAEAD == nil || c.recvAEADEpoch != c.recvEpoch {
		a, err := c.newAEADFor(c.keys.baseRecv, c.recvEpoch)
		if err != nil {
			return 0, err
		}
		c.recvAEAD = a
		c.recvAEADEpoch = c.recvEpoch
	}
	aead := c.recvAEAD

	plaintext, err := aead.Open(nil, header, ciphertext, header)
	if err != nil {
		return 0, fmt.Errorf("decryption failed: epoch=%d seq=%d: %w", epoch, seq, err)
	}
	c.recvSeq++

	c.readBuf.Write(plaintext)
	return c.readBuf.Read(p)
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
