package snell

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/metacubex/mihomo/log"
)

const (
	Version5 = 5

	v5HeaderLen    = 7
	v5EncHeaderLen = v5HeaderLen + 16 // 23 = header + AEAD tag
	v5TagLen       = 16
	v5MaxPayload   = 0x3FFF
	v5TypeData     = 4
)

// v5Conn wraps a net.Conn with Snell v5 AEAD encryption.
// Each direction has its own salt, key, and nonce counter.
type v5Conn struct {
	net.Conn
	cipher       *snellCipher
	sendAEAD     cipher.AEAD
	recvAEAD     cipher.AEAD
	sendNonce    [12]byte
	recvNonce    [12]byte
	recvBuf      []byte // leftover decrypted data from previous read
	sentSalt     bool
	recvdSalt    bool
	mu           sync.Mutex // protects writes
	psk          []byte
	lazyResponse bool // if true, read CONNECT response on first Read()
	lazyDone     bool
}

func newV5Conn(conn net.Conn, psk []byte) (*v5Conn, error) {
	sc := &snellCipher{
		psk:      psk,
		keySize:  16,
		makeAEAD: aesGCM,
	}

	// Generate client salt and derive send key
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	sendAEAD, err := sc.Encrypter(salt)
	if err != nil {
		return nil, err
	}

	// Write salt immediately
	if _, err := conn.Write(salt); err != nil {
		return nil, err
	}

	return &v5Conn{
		Conn:     conn,
		cipher:   sc,
		sendAEAD: sendAEAD,
		sentSalt: true,
		psk:      psk,
	}, nil
}

// initRecv reads server salt and initializes decryption.
func (c *v5Conn) initRecv() error {
	if c.recvdSalt {
		return nil
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	var err error
	c.recvAEAD, err = c.cipher.Decrypter(salt)
	if err != nil {
		return err
	}
	c.recvdSalt = true
	return nil
}

func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// writeFrame encrypts and writes a single frame.
func (c *v5Conn) writeFrame(payload []byte) error {
	payloadLen := len(payload)

	// Build 7-byte header: [type=4, reserved=0x0000, padding_len=0x0000, payload_len BE]
	var header [v5HeaderLen]byte
	header[0] = v5TypeData
	header[5] = byte(payloadLen >> 8)
	header[6] = byte(payloadLen)

	// Encrypt header
	encHeader := c.sendAEAD.Seal(nil, c.sendNonce[:], header[:], nil)
	incrementNonce(c.sendNonce[:])

	if payloadLen == 0 {
		_, err := c.Conn.Write(encHeader)
		return err
	}

	// Encrypt payload
	encPayload := c.sendAEAD.Seal(nil, c.sendNonce[:], payload, nil)
	incrementNonce(c.sendNonce[:])

	// Write header + payload in one call
	buf := make([]byte, len(encHeader)+len(encPayload))
	copy(buf, encHeader)
	copy(buf[len(encHeader):], encPayload)
	_, err := c.Conn.Write(buf)
	return err
}

// readFrame decrypts one frame and returns the payload.
func (c *v5Conn) readFrame() ([]byte, error) {
	if err := c.initRecv(); err != nil {
		return nil, err
	}

	// Read encrypted header (23 bytes)
	encHeader := make([]byte, v5EncHeaderLen)
	if _, err := io.ReadFull(c.Conn, encHeader); err != nil {
		return nil, err
	}

	header, err := c.recvAEAD.Open(nil, c.recvNonce[:], encHeader, nil)
	if err != nil {
		log.Debugln("[Snell-v5] header decrypt failed, nonce=%x, enc_len=%d", c.recvNonce[:], len(encHeader))
		return nil, fmt.Errorf("v5: header decrypt failed: %w", err)
	}
	incrementNonce(c.recvNonce[:])

	if len(header) != v5HeaderLen {
		return nil, errors.New("v5: invalid header length")
	}

	paddingLen := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(header[5:7]))

	if paddingLen == 0 && payloadLen == 0 {
		return nil, nil // zero chunk
	}

	encPayloadLen := payloadLen + v5TagLen

	if paddingLen > 0 {
		if payloadLen == 0 {
			// Skip padding only
			skip := make([]byte, paddingLen)
			_, err = io.ReadFull(c.Conn, skip)
			return nil, err
		}

		// Read padding + encrypted payload contiguously
		total := paddingLen + encPayloadLen
		buf := make([]byte, total)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return nil, err
		}

		// Undo byte interleave swap
		swapLimit := paddingLen
		if encPayloadLen < swapLimit {
			swapLimit = encPayloadLen
		}
		for i := 0; i < swapLimit; i += 2 {
			buf[i], buf[paddingLen+i] = buf[paddingLen+i], buf[i]
		}

		// Decrypt payload portion
		decrypted, err := c.recvAEAD.Open(nil, c.recvNonce[:], buf[paddingLen:], nil)
		if err != nil {
			return nil, errors.New("v5: payload decrypt failed")
		}
		incrementNonce(c.recvNonce[:])
		return decrypted, nil
	}

	// No padding: read encrypted payload directly
	encPayload := make([]byte, encPayloadLen)
	if _, err := io.ReadFull(c.Conn, encPayload); err != nil {
		return nil, err
	}

	decrypted, err := c.recvAEAD.Open(nil, c.recvNonce[:], encPayload, nil)
	if err != nil {
		return nil, errors.New("v5: payload decrypt failed")
	}
	incrementNonce(c.recvNonce[:])
	return decrypted, nil
}

// EnableLazyResponse defers CONNECT response reading to first Read() call.
func (c *v5Conn) EnableLazyResponse() {
	c.lazyResponse = true
}

// Read implements net.Conn. Reads decrypted data.
func (c *v5Conn) Read(b []byte) (int, error) {
	// Lazy init: read CONNECT response on first Read()
	if c.lazyResponse && !c.lazyDone {
		c.lazyDone = true
		initialData, err := ReadV5Response(c)
		if err != nil {
			return 0, err
		}
		if len(initialData) > 0 {
			c.recvBuf = append(c.recvBuf, initialData...)
		}
	}

	// Drain buffered data first
	if len(c.recvBuf) > 0 {
		n := copy(b, c.recvBuf)
		c.recvBuf = c.recvBuf[n:]
		return n, nil
	}

	payload, err := c.readFrame()
	if err != nil {
		return 0, err
	}
	if payload == nil {
		return 0, io.EOF
	}

	n := copy(b, payload)
	if n < len(payload) {
		c.recvBuf = payload[n:]
	}
	return n, nil
}

// Write implements net.Conn. Encrypts and writes data.
func (c *v5Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	total := 0
	for len(b) > 0 {
		size := len(b)
		if size > v5MaxPayload {
			size = v5MaxPayload
		}
		if err := c.writeFrame(b[:size]); err != nil {
			return total, err
		}
		b = b[size:]
		total += size
	}
	return total, nil
}

// WriteV5Header writes the CONNECT command for v5.
func WriteV5Header(conn *v5Conn, host string, port uint) error {
	log.Debugln("[Snell-v5] WriteHeader: %s:%d", host, port)
	buf := make([]byte, 0, 6+len(host))
	buf = append(buf, Version)    // version = 1
	buf = append(buf, CommandConnect) // cmd = 1
	buf = append(buf, 0)          // user_len = 0
	buf = append(buf, byte(len(host)))
	buf = append(buf, []byte(host)...)
	buf = append(buf, byte(port>>8), byte(port))
	return conn.writeFrame(buf)
}

// ReadV5Response reads the CONNECT response.
// Returns any initial relay data bundled with the response.
func ReadV5Response(conn *v5Conn) ([]byte, error) {
	log.Debugln("[Snell-v5] ReadResponse: waiting for server salt...")
	payload, err := conn.readFrame()
	if err != nil {
		return nil, err
	}
	if payload == nil || len(payload) == 0 {
		return nil, errors.New("v5: empty response")
	}
	if payload[0] != 0 {
		return nil, errors.New("v5: server rejected connection")
	}
	// Return data after status byte (may contain initial relay data)
	if len(payload) > 1 {
		return payload[1:], nil
	}
	return nil, nil
}

// StreamV5Conn creates a Snell v5 encrypted connection.
func StreamV5Conn(conn net.Conn, psk []byte) (*v5Conn, error) {
	return newV5Conn(conn, psk)
}
