package vless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/gofrs/uuid"
	xtls "github.com/xtls/go"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	net.Conn
	dst      *DstAddr
	id       *uuid.UUID
	addons   *Addons
	received bool
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.received {
		return vc.Conn.Read(b)
	}

	if err := vc.recvResponse(); err != nil {
		return 0, err
	}
	vc.received = true
	return vc.Conn.Read(b)
}

func (vc *Conn) sendRequest() error {
	buf := &bytes.Buffer{}

	buf.WriteByte(Version)   // protocol version
	buf.Write(vc.id.Bytes()) // 16 bytes of uuid

	if vc.addons != nil {
		bytes, err := proto.Marshal(vc.addons)
		if err != nil {
			return err
		}

		buf.WriteByte(byte(len(bytes)))
		buf.Write(bytes)
	} else {
		buf.WriteByte(0) // addon data length. 0 means no addon data
	}

	if vc.dst.Mux {
		buf.WriteByte(CommandMux)
	} else {
		if vc.dst.UDP {
			buf.WriteByte(CommandUDP)
		} else {
			buf.WriteByte(CommandTCP)
		}

		// Port AddrType Addr
		binary.Write(buf, binary.BigEndian, vc.dst.Port)
		buf.WriteByte(vc.dst.AddrType)
		buf.Write(vc.dst.Addr)
	}

	_, err := vc.Conn.Write(buf.Bytes())
	return err
}

func (vc *Conn) recvResponse() error {
	var err error
	buf := make([]byte, 1)
	_, err = io.ReadFull(vc.Conn, buf)
	if err != nil {
		return err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	_, err = io.ReadFull(vc.Conn, buf)
	if err != nil {
		return err
	}

	length := int64(buf[0])
	if length != 0 { // addon data length > 0
		io.CopyN(io.Discard, vc.Conn, length) // just discard
	}

	return nil
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (*Conn, error) {
	c := &Conn{
		Conn: conn,
		id:   client.uuid,
		dst:  dst,
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
