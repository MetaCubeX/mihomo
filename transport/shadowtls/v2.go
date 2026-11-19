package shadowtls

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"sync"

	"github.com/metacubex/mihomo/log"
)

type hashReadConn struct {
	net.Conn
	reader *bufio.Reader
	hmac   hash.Hash
}

func newHashReadConn(conn net.Conn, password string) *hashReadConn {
	readHMAC := hmac.New(sha1.New, []byte(password))
	reader := bufio.NewReaderSize(io.TeeReader(conn, readHMAC), 16*1024)
	return &hashReadConn{Conn: conn, reader: reader, hmac: readHMAC}
}

func (c *hashReadConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *hashReadConn) Sum() []byte {
	return append([]byte(nil), c.hmac.Sum(nil)[:8]...)
}

type hashWriteConn struct {
	net.Conn
	mu         sync.Mutex
	hmac       hash.Hash
	hasContent bool
	lastSum    []byte
}

func newHashWriteConn(conn net.Conn, password string) *hashWriteConn {
	return &hashWriteConn{Conn: conn, hmac: hmac.New(sha1.New, []byte(password))}
}

func (c *hashWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.Conn.Write(p)
	if c.hmac != nil && n > 0 {
		if c.hasContent {
			c.lastSum = append(c.lastSum[:0], c.hmac.Sum(nil)[:8]...)
		}
		_, _ = c.hmac.Write(p[:n])
		c.hasContent = true
	}
	return n, err
}

func (c *hashWriteConn) sums() (current, previous []byte, hasContent bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hmac != nil {
		current = append([]byte(nil), c.hmac.Sum(nil)[:8]...)
	}
	previous = append([]byte(nil), c.lastSum...)
	return current, previous, c.hasContent
}

func (c *hashWriteConn) Fallback() {
	c.mu.Lock()
	c.hmac = nil
	c.mu.Unlock()
}

type shadowConn struct {
	net.Conn
	readRemaining    int
	readHeader       [tlsHeaderSize]byte
	readHeaderOffset int
	writeMu          sync.Mutex
}

func newConn(conn net.Conn) *shadowConn {
	return &shadowConn{Conn: conn}
}

func (c *shadowConn) Read(p []byte) (int, error) {
	if c.readRemaining > 0 {
		if len(p) > c.readRemaining {
			p = p[:c.readRemaining]
		}
		n, err := c.Conn.Read(p)
		c.readRemaining -= n
		return n, err
	}
	// Keep an incomplete header so a read deadline only interrupts the current Read.
	n, err := io.ReadFull(c.Conn, c.readHeader[c.readHeaderOffset:])
	c.readHeaderOffset += n
	if err != nil {
		return 0, err
	}
	c.readHeaderOffset = 0
	if c.readHeader[0] != applicationData {
		return 0, fmt.Errorf("shadow-tls: unexpected TLS record type: %d", c.readHeader[0])
	}
	length := int(binary.BigEndian.Uint16(c.readHeader[3:]))
	readLength := len(p)
	if readLength > length {
		readLength = length
	}
	n, err = c.Conn.Read(p[:readLength])
	c.readRemaining = length - n
	return n, err
}

func (c *shadowConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := len(p)
	if total == 0 {
		if err := c.writeRecord(nil); err != nil {
			return 0, err
		}
		return 0, nil
	}
	for len(p) > 0 {
		length := len(p)
		if length > maxTLSPlaintext {
			length = maxTLSPlaintext
		}
		if err := c.writeRecord(p[:length]); err != nil {
			return total - len(p), err
		}
		p = p[length:]
	}
	return total, nil
}

func (c *shadowConn) writeRecord(p []byte) error {
	var header [tlsHeaderSize]byte
	header[0] = applicationData
	header[1] = 3
	header[2] = 3
	binary.BigEndian.PutUint16(header[3:], uint16(len(p)))
	return writeBuffers(c.Conn, header[:], p)
}

func (c *shadowConn) Upstream() any { return c.Conn }

type clientConn struct {
	*shadowConn
	mu       sync.Mutex
	hashConn *hashReadConn
}

func newClientConn(hashConn *hashReadConn) *clientConn {
	return &clientConn{shadowConn: newConn(hashConn.Conn), hashConn: hashConn}
}

func (c *clientConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hashConn == nil {
		return c.shadowConn.Write(p)
	}
	prefixed := make([]byte, 8+len(p))
	copy(prefixed, c.hashConn.Sum())
	copy(prefixed[8:], p)
	c.hashConn = nil
	if _, err := c.shadowConn.Write(prefixed); err != nil {
		return 0, err
	}
	return len(p), nil
}

func copyUntilHandshakeFinishedV2(dst net.Conn, src io.Reader, hashConn *hashWriteConn, fallbackAfter int) ([]byte, error) {
	applicationDataCount := 0
	for {
		frame, err := readFrame(src)
		if err != nil {
			return nil, err
		}
		if frame[0] == applicationData {
			payload := frame[tlsHeaderSize:]
			current, previous, hasContent := hashConn.sums()
			if hasContent && len(payload) >= 8 {
				if bytes.Equal(payload[:8], current) {
					log.Debugln("[ShadowTLS] match current hashcode")
					return append([]byte(nil), payload[8:]...), nil
				}
				if len(previous) > 0 && bytes.Equal(payload[:8], previous) {
					log.Debugln("[ShadowTLS] match last hashcode")
					return append([]byte(nil), payload[8:]...), nil
				}
				log.Debugln("[ShadowTLS] hashcode mismatch")
			}
			applicationDataCount++
		}
		if _, err = dst.Write(frame); err != nil {
			return nil, err
		}
		if applicationDataCount > fallbackAfter {
			return nil, os.ErrPermission
		}
	}
}
