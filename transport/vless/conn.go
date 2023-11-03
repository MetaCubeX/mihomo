package vless

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	N.ExtendedWriter
	N.ExtendedReader
	net.Conn
	dst      *DstAddr
	id       *uuid.UUID
	addons   *Addons
	received bool

	handshakeMutex sync.Mutex
	needHandshake  bool
	err            error
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.received {
		return vc.ExtendedReader.Read(b)
	}

	if err := vc.recvResponse(); err != nil {
		return 0, err
	}
	vc.received = true
	return vc.ExtendedReader.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if vc.received {
		return vc.ExtendedReader.ReadBuffer(buffer)
	}

	if err := vc.recvResponse(); err != nil {
		return err
	}
	vc.received = true
	return vc.ExtendedReader.ReadBuffer(buffer)
}

func (vc *Conn) Write(p []byte) (int, error) {
	if vc.needHandshake {
		vc.handshakeMutex.Lock()
		if vc.needHandshake {
			vc.needHandshake = false
			if vc.sendRequest(p) {
				vc.handshakeMutex.Unlock()
				if vc.err != nil {
					return 0, vc.err
				}
				return len(p), vc.err
			}
			if vc.err != nil {
				vc.handshakeMutex.Unlock()
				return 0, vc.err
			}
		}
		vc.handshakeMutex.Unlock()
	}

	return vc.ExtendedWriter.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if vc.needHandshake {
		vc.handshakeMutex.Lock()
		if vc.needHandshake {
			vc.needHandshake = false
			if vc.sendRequest(buffer.Bytes()) {
				vc.handshakeMutex.Unlock()
				return vc.err
			}
			if vc.err != nil {
				vc.handshakeMutex.Unlock()
				return vc.err
			}
		}
		vc.handshakeMutex.Unlock()
	}

	return vc.ExtendedWriter.WriteBuffer(buffer)
}

func (vc *Conn) sendRequest(p []byte) bool {
	var addonsBytes []byte
	if vc.addons != nil {
		addonsBytes, vc.err = proto.Marshal(vc.addons)
		if vc.err != nil {
			return true
		}
	}

	var buffer *buf.Buffer
	if vc.IsXTLSVisionEnabled() {
		buffer = buf.New()
		defer buffer.Release()
	} else {
		requestLen := 1  // protocol version
		requestLen += 16 // UUID
		requestLen += 1  // addons length
		requestLen += len(addonsBytes)
		requestLen += 1 // command
		if !vc.dst.Mux {
			requestLen += 2 // port
			requestLen += 1 // addr type
			requestLen += len(vc.dst.Addr)
		}
		requestLen += len(p)

		buffer = buf.NewSize(requestLen)
		defer buffer.Release()
	}

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

	_, vc.err = vc.ExtendedWriter.Write(buffer.Bytes())
	return true
}

func (vc *Conn) recvResponse() error {
	var buffer [2]byte
	_, vc.err = io.ReadFull(vc.ExtendedReader, buffer[:])
	if vc.err != nil {
		return vc.err
	}

	if buffer[0] != Version {
		return errors.New("unexpected response version")
	}

	length := int64(buffer[1])
	if length != 0 { // addon data length > 0
		io.CopyN(io.Discard, vc.ExtendedReader, length) // just discard
	}

	return nil
}

func (vc *Conn) Upstream() any {
	return vc.Conn
}

func (vc *Conn) NeedHandshake() bool {
	return vc.needHandshake
}

func (vc *Conn) IsXTLSVisionEnabled() bool {
	return vc.addons != nil && vc.addons.Flow == XRV
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (net.Conn, error) {
	c := &Conn{
		ExtendedReader: N.NewExtendedReader(conn),
		ExtendedWriter: N.NewExtendedWriter(conn),
		Conn:           conn,
		id:             client.uuid,
		dst:            dst,
		needHandshake:  true,
	}

	if client.Addons != nil {
		switch client.Addons.Flow {
		case XRV:
			visionConn, err := vision.NewConn(c, c.id)
			if err != nil {
				return nil, err
			}
			c.addons = client.Addons
			return visionConn, nil
		}
	}

	return c, nil
}
