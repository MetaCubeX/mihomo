package nowhere

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

type morphKeys struct{ tcpUp, tcpDown, udpUp, udpDown [32]byte }

func newMorphKeys(password string) *morphKeys {
	k := new(morphKeys)
	for label, dest := range map[string]*[32]byte{"tcp c2s": &k.tcpUp, "tcp s2c": &k.tcpDown, "udp c2s": &k.udpUp, "udp s2c": &k.udpDown} {
		_, _ = io.ReadFull(hkdf.New(sha256.New, []byte(password), []byte("nowhere/morph"), []byte(label)), dest[:])
	}
	return k
}

type morphConn struct {
	net.Conn
	rmu, wmu sync.Mutex
	r, w     *chacha20.Cipher
	rn, wn   uint64
}

func wrapMorphTCP(conn net.Conn, keys *morphKeys, client, full8 bool) (net.Conn, error) {
	var bootstrap [76]byte
	if client {
		if _, err := rand.Read(bootstrap[:]); err != nil {
			return nil, err
		}
		if !full8 {
			for i := 0; i < 64; i++ {
				bootstrap[i] &= 127
			}
		}
		if err := writeFull(conn, bootstrap[:64]); err != nil {
			return nil, err
		}
		if err := writeFull(conn, bootstrap[64:]); err != nil {
			return nil, err
		}
	} else if _, err := io.ReadFull(conn, bootstrap[:]); err != nil {
		return nil, err
	}
	rk, wk := keys.tcpUp, keys.tcpDown
	if client {
		rk, wk = wk, rk
	}
	r, _ := chacha20.NewUnauthenticatedCipher(rk[:], bootstrap[64:])
	w, _ := chacha20.NewUnauthenticatedCipher(wk[:], bootstrap[64:])
	return &morphConn{Conn: conn, r: r, w: w}, nil
}

const morphLimit = 1<<38 - 64

func (c *morphConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if uint64(len(b)) > morphLimit-c.rn {
		return 0, errors.New("nowhere: Morph read counter exhausted")
	}
	n, err := c.Conn.Read(b)
	c.r.XORKeyStream(b[:n], b[:n])
	c.rn += uint64(n)
	return n, err
}
func (c *morphConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if uint64(len(b)) > morphLimit-c.wn {
		return 0, errors.New("nowhere: Morph write counter exhausted")
	}
	out := make([]byte, len(b))
	c.w.XORKeyStream(out, b)
	c.wn += uint64(len(b))
	if err := writeFull(c.Conn, out); err != nil {
		_ = c.Conn.Close()
		return 0, err
	}
	return len(b), nil
}

type morphPacketConn struct {
	net.PacketConn
	readKey, writeKey [32]byte
}

func wrapMorphUDP(pc net.PacketConn, keys *morphKeys, client bool) net.PacketConn {
	r, w := keys.udpUp, keys.udpDown
	if client {
		r, w = w, r
	}
	return &morphPacketConn{pc, r, w}
}
func (c *morphPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buffer := make([]byte, 65535)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, addr, err
		}
		if n <= 12 {
			continue
		}
		cipher, _ := chacha20.NewUnauthenticatedCipher(c.readKey[:], buffer[:12])
		cipher.XORKeyStream(buffer[12:n], buffer[12:n])
		return copy(b, buffer[12:n]), addr, nil
	}
}
func (c *morphPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buffer := make([]byte, 12+len(b))
	if _, err := rand.Read(buffer[:12]); err != nil {
		return 0, err
	}
	cipher, _ := chacha20.NewUnauthenticatedCipher(c.writeKey[:], buffer[:12])
	cipher.XORKeyStream(buffer[12:], b)
	n, err := c.PacketConn.WriteTo(buffer, addr)
	if err == nil && n != len(buffer) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
