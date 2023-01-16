package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/gofrs/uuid"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/network"
	xtls "github.com/xtls/go"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	network.ExtendedConn
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
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()

	common.Must(
		buffer.WriteByte(Version),                 // protocol version
		common.Error(buffer.Write(vc.id.Bytes())), // 16 bytes of uuid
		buffer.WriteByte(byte(len(addonsBytes))),
		common.Error(buffer.Write(addonsBytes)),
	)

	if vc.dst.Mux {
		common.Must(buffer.WriteByte(CommandMux))
	} else {
		if vc.dst.UDP {
			common.Must(buffer.WriteByte(CommandUDP))
		} else {
			common.Must(buffer.WriteByte(CommandTCP))
		}

		binary.BigEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
		common.Must(
			buffer.WriteByte(vc.dst.AddrType),
			common.Error(buffer.Write(vc.dst.Addr)),
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
	if wrapper, ok := vc.ExtendedConn.(*bufio.ExtendedConnWrapper); ok {
		return wrapper.Conn
	}
	return vc.ExtendedConn
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (*Conn, error) {
	c := &Conn{
		ExtendedConn: bufio.NewExtendedConn(conn),
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
