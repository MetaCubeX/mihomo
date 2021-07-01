package vless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"

	"github.com/gofrs/uuid"
)

/*var (

	//proto.Marshal(addons) bytes for Flow: "xtls-rprx-direct"
	addOnBytes, _ = hex.DecodeString("120a1078746c732d727072782d646972656374")
	addOnBytesLen = len(addOnBytes)

	//proto.Marshal(addons) bytes for Flow: ""
	//addOnEmptyBytes, _ = hex.DecodeString("00")
	//addOnEmptyBytesLen  = len(addOnEmptyBytes)
)*/

type Conn struct {
	net.Conn
	dst *DstAddr
	id  *uuid.UUID

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

	// command
	if vc.dst.UDP {
		buf.WriteByte(0) // addon data length. 0 means no addon data
		//buf.WriteByte(byte(addOnEmptyBytesLen))
		//buf.Write(addOnEmptyBytes)
		buf.WriteByte(CommandUDP)
	} else {
		buf.WriteByte(0) // addon data length. 0 means no addon data
		//buf.WriteByte(byte(addOnBytesLen))
		//buf.Write(addOnBytes)
		buf.WriteByte(CommandTCP)
	}

	// Port AddrType Addr
	binary.Write(buf, binary.BigEndian, uint16(vc.dst.Port))
	buf.WriteByte(vc.dst.AddrType)
	buf.Write(vc.dst.Addr)

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
		io.CopyN(ioutil.Discard, vc.Conn, length) // just discard
	}

	return nil
}

// newConn return a Conn instance
func newConn(conn net.Conn, id *uuid.UUID, dst *DstAddr) (*Conn, error) {
	c := &Conn{
		Conn: conn,
		id:   id,
		dst:  dst,
	}
	if err := c.sendRequest(); err != nil {
		return nil, err
	}
	return c, nil
}
