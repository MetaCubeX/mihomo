package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Dreamacro/clash/common/buf"
	N "github.com/Dreamacro/clash/common/net"

	"github.com/gofrs/uuid"
	xtls "github.com/xtls/go"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	N.ExtendedConn
	dst      *DstAddr
	id       *uuid.UUID
	addons   *Addons
	received bool

	handshake      chan struct{}
	handshakeMutex sync.Mutex
	err            error
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.received {
		return vc.ExtendedConn.Read(b)
	}

	if err := vc.recvResponse(); err != nil {
		return 0, err
	}
	vc.received = true
	return vc.ExtendedConn.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if vc.received {
		return vc.ExtendedConn.ReadBuffer(buffer)
	}

	if err := vc.recvResponse(); err != nil {
		return err
	}
	vc.received = true
	return vc.ExtendedConn.ReadBuffer(buffer)
}

func (vc *Conn) Write(p []byte) (int, error) {
	select {
	case <-vc.handshake:
	default:
		if vc.sendRequest(p) {
			if vc.err != nil {
				return 0, vc.err
			}
			return len(p), vc.err
		}
		if vc.err != nil {
			return 0, vc.err
		}
	}
	return vc.ExtendedConn.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) error {
	select {
	case <-vc.handshake:
	default:
		if vc.sendRequest(buffer.Bytes()) {
			return vc.err
		}
		if vc.err != nil {
			return vc.err
		}
	}
	return vc.ExtendedConn.WriteBuffer(buffer)
}

func (vc *Conn) sendRequest(p []byte) bool {
	vc.handshakeMutex.Lock()
	defer vc.handshakeMutex.Unlock()

	select {
	case <-vc.handshake:
		// The handshake has been completed before.
		// So return false to remind the caller.
		return false
	default:
	}
	defer close(vc.handshake)

	requestLen := 1  // protocol version
	requestLen += 16 // UUID
	requestLen += 1  // addons length
	var addonsBytes []byte
	if vc.addons != nil {
		addonsBytes, vc.err = proto.Marshal(vc.addons)
		if vc.err != nil {
			return true
		}
	}
	requestLen += len(addonsBytes)
	requestLen += 1 // command
	if !vc.dst.Mux {
		requestLen += 2 // port
		requestLen += 1 // addr type
		requestLen += len(vc.dst.Addr)
	}
	requestLen += len(p)

	_buffer := buf.StackNewSize(requestLen)
	defer buf.KeepAlive(_buffer)
	buffer := buf.Dup(_buffer)
	defer buffer.Release()

	buf.Must(
		buffer.WriteByte(Version),              // protocol version
		buf.Error(buffer.Write(vc.id.Bytes())), // 16 bytes of uuid
		buffer.WriteByte(byte(len(addonsBytes))),
		buf.Error(buffer.Write(addonsBytes)),
	)

	if vc.dst.Mux {
		buf.Must(buffer.WriteByte(CommandMux))
	} else {
		if vc.dst.UDP {
			buf.Must(buffer.WriteByte(CommandUDP))
		} else {
			buf.Must(buffer.WriteByte(CommandTCP))
		}

		binary.BigEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
		buf.Must(
			buffer.WriteByte(vc.dst.AddrType),
			buf.Error(buffer.Write(vc.dst.Addr)),
		)
	}

	buf.Must(buf.Error(buffer.Write(p)))

	_, vc.err = vc.ExtendedConn.Write(buffer.Bytes())
	return true
}

func (vc *Conn) recvResponse() error {
	var buf [1]byte
	_, vc.err = io.ReadFull(vc.ExtendedConn, buf[:])
	if vc.err != nil {
		return vc.err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	_, vc.err = io.ReadFull(vc.ExtendedConn, buf[:])
	if vc.err != nil {
		return vc.err
	}

	length := int64(buf[0])
	if length != 0 { // addon data length > 0
		io.CopyN(io.Discard, vc.ExtendedConn, length) // just discard
	}

	return nil
}

func (vc *Conn) Upstream() any {
	return vc.ExtendedConn
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (*Conn, error) {
	c := &Conn{
		ExtendedConn: N.NewExtendedConn(conn),
		id:           client.uuid,
		dst:          dst,
		handshake:    make(chan struct{}),
	}

	if !dst.UDP && client.Addons != nil {
		switch client.Addons.Flow {
		case XRO, XRD, XRS:
			if xtlsConn, ok := conn.(*xtls.Conn); ok {
				xtlsConn.RPRX = true
				xtlsConn.SHOW = client.XTLSShow
				xtlsConn.MARK = "XTLS"
				if client.Addons.Flow == XRS {
					client.Addons.Flow = XRD
				}

				if client.Addons.Flow == XRD {
					xtlsConn.DirectMode = true
				}
				c.addons = client.Addons
			} else {
				return nil, fmt.Errorf("failed to use %s, maybe \"security\" is not \"xtls\"", client.Addons.Flow)
			}
		}
	}

	//go func() {
	//	select {
	//	case <-c.handshake:
	//	case <-time.After(200 * time.Millisecond):
	//		c.sendRequest(nil)
	//	}
	//}()
	return c, nil
}
