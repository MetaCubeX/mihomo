package udp

import (
	"github.com/metacubex/mihomo/transport/hysteria/obfs"
	"net"
	"sync"
	"time"
)

const udpBufferSize = 65535

type ObfsUDPConn struct {
	orig       net.PacketConn
	obfs       obfs.Obfuscator
	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewObfsUDPConn(orig net.PacketConn, obfs obfs.Obfuscator) *ObfsUDPConn {
	return &ObfsUDPConn{
		orig:     orig,
		obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
}

func (c *ObfsUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.readMutex.Lock()
		n, addr, err := c.orig.ReadFrom(c.readBuf)
		if n <= 0 {
			c.readMutex.Unlock()
			return 0, addr, err
		}
		newN := c.obfs.Deobfuscate(c.readBuf[:n], p)
		c.readMutex.Unlock()
		if newN > 0 {
			// Valid packet
			return newN, addr, err
		} else if err != nil {
			// Not valid and orig.ReadFrom had some error
			return 0, addr, err
		}
	}
}

func (c *ObfsUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	bn := c.obfs.Obfuscate(p, c.writeBuf)
	_, err = c.orig.WriteTo(c.writeBuf[:bn], addr)
	c.writeMutex.Unlock()
	if err != nil {
		return 0, err
	} else {
		return len(p), nil
	}
}

func (c *ObfsUDPConn) Close() error {
	return c.orig.Close()
}

func (c *ObfsUDPConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *ObfsUDPConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *ObfsUDPConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *ObfsUDPConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}
