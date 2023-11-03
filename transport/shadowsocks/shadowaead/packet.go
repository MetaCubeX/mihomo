package shadowaead

import (
	"crypto/rand"
	"errors"
	"io"
	"net"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
)

// ErrShortPacket means that the packet is too short for a valid encrypted packet.
var ErrShortPacket = errors.New("short packet")

var _zerononce [128]byte // read-only. 128 bytes is more than enough.

// Pack encrypts plaintext using Cipher with a randomly generated salt and
// returns a slice of dst containing the encrypted packet and any error occurred.
// Ensure len(dst) >= ciph.SaltSize() + len(plaintext) + aead.Overhead().
func Pack(dst, plaintext []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:saltSize]
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := ciph.Encrypter(salt)
	if err != nil {
		return nil, err
	}
	if len(dst) < saltSize+len(plaintext)+aead.Overhead() {
		return nil, io.ErrShortBuffer
	}
	b := aead.Seal(dst[saltSize:saltSize], _zerononce[:aead.NonceSize()], plaintext, nil)
	return dst[:saltSize+len(b)], nil
}

// Unpack decrypts pkt using Cipher and returns a slice of dst containing the decrypted payload and any error occurred.
// Ensure len(dst) >= len(pkt) - aead.SaltSize() - aead.Overhead().
func Unpack(dst, pkt []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}
	salt := pkt[:saltSize]
	aead, err := ciph.Decrypter(salt)
	if err != nil {
		return nil, err
	}
	if len(pkt) < saltSize+aead.Overhead() {
		return nil, ErrShortPacket
	}
	if saltSize+len(dst)+aead.Overhead() < len(pkt) {
		return nil, io.ErrShortBuffer
	}
	b, err := aead.Open(dst[:0], _zerononce[:aead.NonceSize()], pkt[saltSize:], nil)
	return b, err
}

type PacketConn struct {
	N.EnhancePacketConn
	Cipher
}

const maxPacketSize = 64 * 1024

// NewPacketConn wraps an N.EnhancePacketConn with cipher
func NewPacketConn(c N.EnhancePacketConn, ciph Cipher) *PacketConn {
	return &PacketConn{EnhancePacketConn: c, Cipher: ciph}
}

// WriteTo encrypts b and write to addr using the embedded PacketConn.
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := pool.Get(maxPacketSize)
	defer pool.Put(buf)
	buf, err := Pack(buf, b, c)
	if err != nil {
		return 0, err
	}
	_, err = c.EnhancePacketConn.WriteTo(buf, addr)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into b.
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.EnhancePacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := Unpack(b[c.Cipher.SaltSize():], b[:n], c)
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return len(bb), addr, err
}

func (c *PacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, addr, err = c.EnhancePacketConn.WaitReadFrom()
	if err != nil {
		return
	}
	data, err = Unpack(data[c.Cipher.SaltSize():], data, c)
	if err != nil {
		if put != nil {
			put()
		}
		data = nil
		put = nil
		return
	}
	return
}
