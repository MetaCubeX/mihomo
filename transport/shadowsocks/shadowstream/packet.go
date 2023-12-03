package shadowstream

import (
	"crypto/rand"
	"errors"
	"io"
	"net"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
)

// ErrShortPacket means the packet is too short to be a valid encrypted packet.
var ErrShortPacket = errors.New("short packet")

// Pack encrypts plaintext using stream cipher s and a random IV.
// Returns a slice of dst containing random IV and ciphertext.
// Ensure len(dst) >= s.IVSize() + len(plaintext).
func Pack(dst, plaintext []byte, s Cipher) ([]byte, error) {
	if len(dst) < s.IVSize()+len(plaintext) {
		return nil, io.ErrShortBuffer
	}
	iv := dst[:s.IVSize()]
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	s.Encrypter(iv).XORKeyStream(dst[len(iv):], plaintext)
	return dst[:len(iv)+len(plaintext)], nil
}

// Unpack decrypts pkt using stream cipher s.
// Returns a slice of dst containing decrypted plaintext.
func Unpack(dst, pkt []byte, s Cipher) ([]byte, error) {
	if len(pkt) < s.IVSize() {
		return nil, ErrShortPacket
	}
	if len(dst) < len(pkt)-s.IVSize() {
		return nil, io.ErrShortBuffer
	}
	iv := pkt[:s.IVSize()]
	s.Decrypter(iv).XORKeyStream(dst, pkt[len(iv):])
	return dst[:len(pkt)-len(iv)], nil
}

type PacketConn struct {
	N.EnhancePacketConn
	Cipher
}

// NewPacketConn wraps an N.EnhancePacketConn with stream cipher encryption/decryption.
func NewPacketConn(c N.EnhancePacketConn, ciph Cipher) *PacketConn {
	return &PacketConn{EnhancePacketConn: c, Cipher: ciph}
}

const maxPacketSize = 64 * 1024

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := pool.Get(maxPacketSize)
	defer pool.Put(buf)
	buf, err := Pack(buf, b, c.Cipher)
	if err != nil {
		return 0, err
	}
	_, err = c.EnhancePacketConn.WriteTo(buf, addr)
	return len(b), err
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.EnhancePacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := Unpack(b[c.IVSize():], b[:n], c.Cipher)
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
	data, err = Unpack(data[c.IVSize():], data, c)
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
