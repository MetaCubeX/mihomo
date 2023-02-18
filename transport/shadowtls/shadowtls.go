package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"

	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
)

const (
	chunkSize           = 1 << 13
	Mode         string = "shadow-tls"
	hashLen      int    = 8
	tlsHeaderLen int    = 5
)

var (
	DefaultALPN = []string{"h2", "http/1.1"}
)

// ShadowTLS is shadow-tls implementation
type ShadowTLS struct {
	net.Conn
	password     []byte
	remain       int
	firstRequest bool
	tlsConfig    *tls.Config
}

type HashedConn struct {
	net.Conn
	hasher hash.Hash
}

func newHashedStream(conn net.Conn, password []byte) HashedConn {
	return HashedConn{
		Conn:   conn,
		hasher: hmac.New(sha1.New, password),
	}
}

func (h HashedConn) Read(b []byte) (n int, err error) {
	n, err = h.Conn.Read(b)
	h.hasher.Write(b[:n])
	return
}

func (s *ShadowTLS) read(b []byte) (int, error) {
	var buf [tlsHeaderLen]byte
	_, err := io.ReadFull(s.Conn, buf[:])
	if err != nil {
		return 0, fmt.Errorf("shadowtls read failed %w", err)
	}
	if buf[0] != 0x17 || buf[1] != 0x3 || buf[2] != 0x3 {
		return 0, fmt.Errorf("invalid shadowtls header %v", buf)
	}
	length := int(binary.BigEndian.Uint16(buf[3:]))

	if length > len(b) {
		n, err := s.Conn.Read(b)
		if err != nil {
			return n, err
		}
		s.remain = length - n
		return n, nil
	}

	return io.ReadFull(s.Conn, b[:length])
}

func (s *ShadowTLS) Read(b []byte) (int, error) {
	if s.remain > 0 {
		length := s.remain
		if length > len(b) {
			length = len(b)
		}

		n, err := io.ReadFull(s.Conn, b[:length])
		if err != nil {
			return n, fmt.Errorf("shadowtls Read failed with %w", err)
		}
		s.remain -= n
		return n, nil
	}

	return s.read(b)
}

func (s *ShadowTLS) Write(b []byte) (int, error) {
	length := len(b)
	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize
		if end > length {
			end = length
		}

		n, err := s.write(b[i:end])
		if err != nil {
			return n, fmt.Errorf("shadowtls Write failed with %w, i=%d, end=%d, n=%d", err, i, end, n)
		}
	}
	return length, nil
}

func (s *ShadowTLS) write(b []byte) (int, error) {
	var hashVal []byte
	if s.firstRequest {
		hashedConn := newHashedStream(s.Conn, s.password)
		tlsConn := tls.Client(hashedConn, s.tlsConfig)
		// fix tls handshake not timeout
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, fmt.Errorf("tls connect failed with %w", err)
		}
		hashVal = hashedConn.hasher.Sum(nil)[:hashLen]
		s.firstRequest = false
	}

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	buf.Write([]byte{0x17, 0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint16(len(b)+len(hashVal)))
	buf.Write(hashVal)
	buf.Write(b)
	_, err := s.Conn.Write(buf.Bytes())
	if err != nil {
		// return 0 because errors occur here make the
		// whole situation irrecoverable
		return 0, err
	}
	return len(b), nil
}

// NewShadowTLS return a ShadowTLS
func NewShadowTLS(conn net.Conn, password string, tlsConfig *tls.Config) net.Conn {
	return &ShadowTLS{
		Conn:         conn,
		password:     []byte(password),
		firstRequest: true,
		tlsConfig:    tlsConfig,
	}
}
