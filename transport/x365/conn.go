package x365

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/gofrs/uuid/v5"
)

type Conn struct {
	N.ExtendedConn
	dst      *DstAddr
	id       uuid.UUID
	received bool
	sent     bool
}

func (c *Conn) Read(b []byte) (int, error) {
	if !c.received {
		if err := c.recvResponse(); err != nil {
			return 0, err
		}
		c.received = true
	}
	return c.ExtendedConn.Read(b)
}

func (c *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if !c.received {
		if err := c.recvResponse(); err != nil {
			return err
		}
		c.received = true
	}
	return c.ExtendedConn.ReadBuffer(buffer)
}

func (c *Conn) Write(p []byte) (int, error) {
	if !c.sent {
		if err := c.sendRequest(p); err != nil {
			return 0, err
		}
		c.sent = true
		return len(p), nil
	}

	return c.ExtendedConn.Write(p)
}

func (c *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.sent {
		defer buffer.Release()
		if err := c.sendRequest(buffer.Bytes()); err != nil {
			return err
		}
		c.sent = true
		return nil
	}

	return c.ExtendedConn.WriteBuffer(buffer)
}

// sendRequest writes the request header followed by the first payload:
// magic(4) | version(1) | command(1) | uuid(16) | port(2) | atyp(1) | addr
func (c *Conn) sendRequest(p []byte) error {
	requestLen := len(Magic)
	requestLen += 1  // version
	requestLen += 1  // command
	requestLen += 16 // UUID
	requestLen += 2  // port
	requestLen += 1  // addr type
	requestLen += len(c.dst.Addr)
	requestLen += len(p)

	buffer := buf.NewSize(requestLen)
	defer buffer.Release()

	buf.Must(
		buf.Error(buffer.Write(Magic[:])),
		buffer.WriteByte(Version),
		buffer.WriteByte(CommandTCP),
		buf.Error(buffer.Write(c.id.Bytes())),
	)
	binary.BigEndian.PutUint16(buffer.Extend(2), c.dst.Port)
	buf.Must(
		buffer.WriteByte(c.dst.AddrType),
		buf.Error(buffer.Write(c.dst.Addr)),
		buf.Error(buffer.Write(p)),
	)

	_, err := c.ExtendedConn.Write(buffer.Bytes())
	return err
}

// recvResponse consumes the response header: magic(4) | status(1)
func (c *Conn) recvResponse() error {
	var buffer [len(Magic) + 1]byte
	if _, err := io.ReadFull(c.ExtendedConn, buffer[:]); err != nil {
		return err
	}

	if !bytes.Equal(buffer[:len(Magic)], Magic[:]) {
		return errors.New("unexpected response magic")
	}
	if status := buffer[4]; status != StatusOK {
		return fmt.Errorf("server rejected the request with status 0x%02x", status)
	}

	return nil
}

func (c *Conn) Upstream() any {
	return c.ExtendedConn
}

func (c *Conn) ReaderReplaceable() bool {
	return c.received
}

func (c *Conn) WriterReplaceable() bool {
	return c.sent
}

func (c *Conn) NeedHandshake() bool {
	return !c.sent
}

func newConn(conn net.Conn, client *Client, dst *DstAddr) *Conn {
	return &Conn{
		ExtendedConn: N.NewExtendedConn(conn),
		id:           client.uuid,
		dst:          dst,
	}
}
