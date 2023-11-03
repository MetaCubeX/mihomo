package faketcp

import (
	"github.com/metacubex/mihomo/transport/hysteria/obfs"
	"net"
	"sync"
	"syscall"
	"time"
)

const udpBufferSize = 65535

type ObfsFakeTCPConn struct {
	orig       *TCPConn
	obfs       obfs.Obfuscator
	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewObfsFakeTCPConn(orig *TCPConn, obfs obfs.Obfuscator) *ObfsFakeTCPConn {
	return &ObfsFakeTCPConn{
		orig:     orig,
		obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
}

func (c *ObfsFakeTCPConn) ReadFrom(p []byte) (int, net.Addr, error) {
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

func (c *ObfsFakeTCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

func (c *ObfsFakeTCPConn) Close() error {
	return c.orig.Close()
}

func (c *ObfsFakeTCPConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *ObfsFakeTCPConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *ObfsFakeTCPConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *ObfsFakeTCPConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}

func (c *ObfsFakeTCPConn) SetReadBuffer(bytes int) error {
	return c.orig.SetReadBuffer(bytes)
}

func (c *ObfsFakeTCPConn) SetWriteBuffer(bytes int) error {
	return c.orig.SetWriteBuffer(bytes)
}

func (c *ObfsFakeTCPConn) SyscallConn() (syscall.RawConn, error) {
	return c.orig.SyscallConn()
}
