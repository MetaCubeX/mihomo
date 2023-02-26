package vless

import (
	"bytes"
	"crypto/subtle"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"unsafe"

	"github.com/Dreamacro/clash/common/buf"
	N "github.com/Dreamacro/clash/common/net"
	tlsC "github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/log"

	"github.com/gofrs/uuid"
	utls "github.com/sagernet/utls"
	xtls "github.com/xtls/go"
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

	handshake      chan struct{}
	handshakeMutex sync.Mutex
	err            error

	tlsConn  net.Conn
	input    *bytes.Reader
	rawInput *bytes.Buffer

	packetsToFilter            int
	isTLS                      bool
	isTLS12orAbove             bool
	enableXTLS                 bool
	cipher                     uint16
	remainingServerHello       uint16
	readRemainingContent       int
	readRemainingPadding       int
	readProcess                bool
	readFilterUUID             bool
	readLastCommand            byte
	writeFilterApplicationData bool
	writeDirect                bool
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.received {
		if vc.readProcess {
			buffer := buf.With(b)
			err := vc.ReadBuffer(buffer)
			return buffer.Len(), err
		}
		return vc.ExtendedReader.Read(b)
	}

	if err := vc.recvResponse(); err != nil {
		return 0, err
	}
	vc.received = true
	return vc.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if vc.received {
		toRead := buffer.FreeBytes()
		if vc.readRemainingContent > 0 {
			if vc.readRemainingContent < buffer.FreeLen() {
				toRead = toRead[:vc.readRemainingContent]
			}
			n, err := vc.ExtendedReader.Read(toRead)
			buffer.Truncate(n)
			vc.readRemainingContent -= n
			vc.FilterTLS(toRead)
			return err
		}
		if vc.readRemainingPadding > 0 {
			_, err := io.CopyN(io.Discard, vc.ExtendedReader, int64(vc.readRemainingPadding))
			if err != nil {
				return err
			}
			vc.readRemainingPadding = 0
		}
		if vc.readProcess {
			switch vc.readLastCommand {
			case commandPaddingContinue:
				//if vc.isTLS || vc.packetsToFilter > 0 {
				headerUUIDLen := 0
				if vc.readFilterUUID {
					headerUUIDLen = uuid.Size
				}
				var header []byte
				if need := headerUUIDLen + paddingHeaderLen; buffer.FreeLen() < need {
					header = make([]byte, need)
				} else {
					header = buffer.FreeBytes()[:need]
				}
				_, err := io.ReadFull(vc.ExtendedReader, header)
				if err != nil {
					return err
				}
				pos := 0
				if vc.readFilterUUID {
					vc.readFilterUUID = false
					pos = uuid.Size
					if subtle.ConstantTimeCompare(vc.id.Bytes(), header[:uuid.Size]) != 1 {
						err = fmt.Errorf("XTLS Vision server responded unknown UUID: %s",
							uuid.FromBytesOrNil(header[:uuid.Size]).String())
						log.Errorln(err.Error())
						return err
					}
				}
				vc.readLastCommand = header[pos]
				vc.readRemainingContent = int(binary.BigEndian.Uint16(header[pos+1:]))
				vc.readRemainingPadding = int(binary.BigEndian.Uint16(header[pos+3:]))
				log.Debugln("XTLS Vision read padding: command=%d, payloadLen=%d, paddingLen=%d",
					vc.readLastCommand, vc.readRemainingContent, vc.readRemainingPadding)
				return vc.ReadBuffer(buffer)
				//}
			case commandPaddingEnd:
				vc.readProcess = false
				return vc.ReadBuffer(buffer)
			case commandPaddingDirect:
				needReturn := false
				if vc.input != nil {
					_, err := buffer.ReadFrom(vc.input)
					if err != nil {
						return err
					}
					if vc.input.Len() == 0 {
						needReturn = true
						vc.input = nil
					} else { // buffer is full
						return nil
					}
				}
				if vc.rawInput != nil {
					_, err := buffer.ReadFrom(vc.rawInput)
					if err != nil {
						return err
					}
					needReturn = true
					if vc.rawInput.Len() == 0 {
						vc.rawInput = nil
					}
				}
				if vc.input == nil && vc.rawInput == nil {
					vc.readProcess = false
					vc.ExtendedReader = N.NewExtendedReader(vc.Conn)
					log.Debugln("XTLS Vision direct read start")
				}
				if needReturn {
					return nil
				}
			default:
				err := fmt.Errorf("XTLS Vision read unknown command: %d", vc.readLastCommand)
				log.Debugln(err.Error())
				return err
			}
		}
		return vc.ExtendedReader.ReadBuffer(buffer)
	}

	if err := vc.recvResponse(); err != nil {
		return err
	}
	vc.received = true
	return vc.ReadBuffer(buffer)
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
	if vc.writeFilterApplicationData {
		_buffer := buf.StackNew()
		defer buf.KeepAlive(_buffer)
		buffer := buf.Dup(_buffer)
		defer buffer.Release()
		buffer.Write(p)
		err := vc.WriteBuffer(buffer)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return vc.ExtendedWriter.Write(p)
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
	if vc.writeFilterApplicationData {
		buffer2 := ReshapeBuffer(buffer)
		defer buffer2.Release()
		vc.FilterTLS(buffer.Bytes())
		command := commandPaddingContinue
		if !vc.isTLS {
			command = commandPaddingEnd

			// disable XTLS
			vc.readProcess = false
			vc.writeFilterApplicationData = false
			vc.packetsToFilter = 0
		} else if buffer.Len() > 6 && bytes.Equal(buffer.To(3), tlsApplicationDataStart) || vc.packetsToFilter <= 0 {
			command = commandPaddingEnd
			if vc.enableXTLS {
				command = commandPaddingDirect
				vc.writeDirect = true
			}
			vc.writeFilterApplicationData = false
		}
		ApplyPadding(buffer, command, nil)
		err := vc.ExtendedWriter.WriteBuffer(buffer)
		if err != nil {
			return err
		}
		if vc.writeDirect {
			vc.ExtendedWriter = N.NewExtendedWriter(vc.Conn)
			log.Debugln("XTLS Vision direct write start")
			//time.Sleep(10 * time.Millisecond)
		}
		if buffer2 != nil {
			if vc.writeDirect || !vc.isTLS {
				return vc.ExtendedWriter.WriteBuffer(buffer2)
			}
			vc.FilterTLS(buffer2.Bytes())
			command = commandPaddingContinue
			if buffer2.Len() > 6 && bytes.Equal(buffer2.To(3), tlsApplicationDataStart) || vc.packetsToFilter <= 0 {
				command = commandPaddingEnd
				if vc.enableXTLS {
					command = commandPaddingDirect
					vc.writeDirect = true
				}
				vc.writeFilterApplicationData = false
			}
			ApplyPadding(buffer2, command, nil)
			err = vc.ExtendedWriter.WriteBuffer(buffer2)
			if vc.writeDirect {
				vc.ExtendedWriter = N.NewExtendedWriter(vc.Conn)
				log.Debugln("XTLS Vision direct write start")
				//time.Sleep(10 * time.Millisecond)
			}
		}
		return err
	}
	/*if vc.writeDirect {
		log.Debugln("XTLS Vision Direct write, payloadLen=%d", buffer.Len())
	}*/
	return vc.ExtendedWriter.WriteBuffer(buffer)
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

	var addonsBytes []byte
	if vc.addons != nil {
		addonsBytes, vc.err = proto.Marshal(vc.addons)
		if vc.err != nil {
			return true
		}
	}
	isVision := vc.IsXTLSVisionEnabled()

	var buffer *buf.Buffer
	if isVision {
		_buffer := buf.StackNew()
		defer buf.KeepAlive(_buffer)
		buffer = buf.Dup(_buffer)
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

		_buffer := buf.StackNewSize(requestLen)
		defer buf.KeepAlive(_buffer)
		buffer = buf.Dup(_buffer)
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

	if isVision && !vc.dst.UDP && !vc.dst.Mux {
		if len(p) == 0 {
			WriteWithPadding(buffer, nil, commandPaddingContinue, vc.id)
		} else {
			vc.FilterTLS(p)
			if vc.isTLS {
				WriteWithPadding(buffer, p, commandPaddingContinue, vc.id)
			} else {
				buf.Must(buf.Error(buffer.Write(p)))

				// disable XTLS
				vc.readProcess = false
				vc.writeFilterApplicationData = false
				vc.packetsToFilter = 0
			}
		}
	} else {
		buf.Must(buf.Error(buffer.Write(p)))
	}

	_, vc.err = vc.ExtendedWriter.Write(buffer.Bytes())
	if vc.err != nil {
		return true
	}
	if isVision {
		switch underlying := vc.tlsConn.(type) {
		case *gotls.Conn:
			if underlying.ConnectionState().Version != gotls.VersionTLS13 {
				vc.err = ErrNotTLS13
			}
		case *utls.UConn:
			if underlying.ConnectionState().Version != utls.VersionTLS13 {
				vc.err = ErrNotTLS13
			}
		default:
			vc.err = fmt.Errorf(`failed to use %s, maybe "security" is not "tls" or "utls"`, vc.addons.Flow)
		}
		vc.tlsConn = nil
	}
	return true
}

func (vc *Conn) recvResponse() error {
	var buf [1]byte
	_, vc.err = io.ReadFull(vc.ExtendedReader, buf[:])
	if vc.err != nil {
		return vc.err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	_, vc.err = io.ReadFull(vc.ExtendedReader, buf[:])
	if vc.err != nil {
		return vc.err
	}

	length := int64(buf[0])
	if length != 0 { // addon data length > 0
		io.CopyN(io.Discard, vc.ExtendedReader, length) // just discard
	}

	return nil
}

func (vc *Conn) FrontHeadroom() int {
	if vc.IsXTLSVisionEnabled() {
		return paddingHeaderLen
	}
	return 0
}

func (vc *Conn) Upstream() any {
	if vc.tlsConn == nil {
		return vc.Conn
	}
	return vc.tlsConn
}

func (vc *Conn) IsXTLSVisionEnabled() bool {
	return vc.addons != nil && vc.addons.Flow == XRV
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (*Conn, error) {
	c := &Conn{
		ExtendedReader: N.NewExtendedReader(conn),
		ExtendedWriter: N.NewExtendedWriter(conn),
		Conn:           conn,
		id:             client.uuid,
		dst:            dst,
		handshake:      make(chan struct{}),
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
		case XRV:
			c.packetsToFilter = 6
			c.readProcess = true
			c.readFilterUUID = true
			c.writeFilterApplicationData = true
			c.addons = client.Addons
			var t reflect.Type
			var p uintptr
			switch underlying := conn.(type) {
			case *gotls.Conn:
				c.Conn = underlying.NetConn()
				c.tlsConn = underlying
				t = reflect.TypeOf(underlying).Elem()
				p = uintptr(unsafe.Pointer(underlying))
			case *utls.UConn:
				c.Conn = underlying.NetConn()
				c.tlsConn = underlying
				t = reflect.TypeOf(underlying.Conn).Elem()
				p = uintptr(unsafe.Pointer(underlying.Conn))
			case *tlsC.UConn:
				c.Conn = underlying.NetConn()
				c.tlsConn = underlying.UConn
				t = reflect.TypeOf(underlying.Conn).Elem()
				p = uintptr(unsafe.Pointer(underlying.Conn))
			default:
				return nil, fmt.Errorf(`failed to use %s, maybe "security" is not "tls" or "utls"`, client.Addons.Flow)
			}
			i, _ := t.FieldByName("input")
			r, _ := t.FieldByName("rawInput")
			c.input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
			c.rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
			// if _, ok := c.Conn.(*net.TCPConn); !ok {
			// 	log.Debugln("XTLS underlying conn is not *net.TCPConn, got %T", c.Conn)
			// }
		}
	}

	return c, nil
}
