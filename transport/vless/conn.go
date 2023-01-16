package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

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

func (vc *Conn) sendRequest() (err error) {
	requestLen := 1  // protocol version
	requestLen += 16 // UUID
	requestLen += 1  // addons length
	var addonsBytes []byte
	if vc.addons != nil {
		addonsBytes, err = proto.Marshal(vc.addons)
		if err != nil {
			return err
		}
	}
	requestLen += len(addonsBytes)
	requestLen += 1 // command
	if !vc.dst.Mux {
		requestLen += 2 // port
		requestLen += 1 // addr type
		requestLen += len(vc.dst.Addr)
	}
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

	_, err = vc.ExtendedConn.Write(buffer.Bytes())
	return
}

func (vc *Conn) recvResponse() error {
	var err error
	var buf [1]byte
	_, err = io.ReadFull(vc.ExtendedConn, buf[:])
	if err != nil {
		return err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	_, err = io.ReadFull(vc.ExtendedConn, buf[:])
	if err != nil {
		return err
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

	if err := c.sendRequest(); err != nil {
		return nil, err
	}
	return c, nil
}
