package echtunnel

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type WSConn struct {
	*websocket.Conn
	reader io.Reader
}

func (c *WSConn) Read(b []byte) (int, error) {
	if c.reader == nil {
		msgType, r, err := c.NextReader()
		if err != nil {
			return 0, err
		}
		if msgType != websocket.BinaryMessage {
			return 0, fmt.Errorf("unexpected message type: %d", msgType)
		}
		c.reader = r
	}

	n, err := c.reader.Read(b)
	if err == io.EOF {
		c.reader = nil
		err = nil
	}
	return n, err
}

func (c *WSConn) Write(b []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WSConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *WSConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *WSConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// PacketConn for UDP
type PacketConn struct {
	net.Conn
}

func NewPacketConn(conn net.Conn) *PacketConn {
	return &PacketConn{Conn: conn}
}

func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := pc.Read(b)
	return n, pc.RemoteAddr(), err
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return pc.Write(b)
}
