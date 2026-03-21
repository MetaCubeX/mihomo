package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"unsafe"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"

	"github.com/gofrs/uuid/v5"
)

var (
	_ N.ExtendedConn = (*Conn)(nil)
)

type Conn struct {
	net.Conn // should be *vless.Conn
	N.ExtendedReader
	N.ExtendedWriter
	userUUID uuid.UUID

	// [*tls.Conn] or other tls-like [net.Conn]'s internal variables
	netConn  net.Conn      // tlsConn.NetConn()
	input    *bytes.Reader // &tlsConn.input or nil
	rawInput *bytes.Buffer // &tlsConn.rawInput or nil

	packetsToFilter            int
	isTLS                      bool
	isTLS12orAbove             bool
	enableXTLS                 bool
	cipher                     uint16
	remainingServerHello       uint16
	readRemainingBuffer        *buf.Buffer
	readRemainingContent       int
	readRemainingPadding       int
	readProcess                bool
	readFilterUUID             bool
	readLastCommand            byte
	writeFilterApplicationData bool
	writeDirect                bool
	writeOnceUserUUID          []byte
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.readProcess {
		buffer := buf.With(b)
		err := vc.ReadBuffer(buffer)
		if unsafe.SliceData(buffer.Bytes()) != unsafe.SliceData(b) { // buffer.Bytes() not at the beginning of b
			copy(b, buffer.Bytes())
		}
		return buffer.Len(), err
	}
	return vc.ExtendedReader.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if vc.readRemainingBuffer != nil {
		_, err := buffer.ReadOnceFrom(vc.readRemainingBuffer)
		if vc.readRemainingBuffer.IsEmpty() {
			vc.readRemainingBuffer.Release()
			vc.readRemainingBuffer = nil
		}
		return err
	}
	if vc.readRemainingContent > 0 {
		readSize := xrayBufSize          // at least read xrayBufSize
		if buffer.FreeLen() > readSize { // input buffer larger than xrayBufSize, read as much as possible
			readSize = buffer.FreeLen()
		}
		if readSize > vc.readRemainingContent { // don't read out of bounds
			readSize = vc.readRemainingContent
		}

		readBuffer := buffer
		if buffer.FreeLen() < readSize {
			readBuffer = buf.NewSize(readSize)
			vc.readRemainingBuffer = readBuffer
		}
		n, err := vc.ExtendedReader.Read(readBuffer.FreeBytes()[:readSize])
		readBuffer.Truncate(n)
		vc.readRemainingContent -= n
		vc.FilterTLS(readBuffer.Bytes())
		if vc.readRemainingBuffer != nil {
			innerErr := vc.ReadBuffer(buffer) // back to top but not losing err
			if err != nil {
				err = innerErr
			}
		}
		return err
	}
	if vc.readRemainingPadding > 0 {
		n, err := io.CopyN(io.Discard, vc.ExtendedReader, int64(vc.readRemainingPadding))
		if err != nil {
			return err
		}
		vc.readRemainingPadding -= int(n)
	}
	if vc.readProcess {
		switch vc.readLastCommand {
		case commandPaddingContinue:
			//if vc.isTLS || vc.packetsToFilter > 0 {
			need := PaddingHeaderLen
			if !vc.readFilterUUID {
				need = PaddingHeaderLen - uuid.Size
			}
			var header []byte
			if buffer.FreeLen() < need {
				header = make([]byte, need)
			} else {
				header = buffer.FreeBytes()[:need]
			}
			_, err := io.ReadFull(vc.ExtendedReader, header)
			if err != nil {
				return err
			}
			if vc.readFilterUUID {
				vc.readFilterUUID = false
				if !bytes.Equal(vc.userUUID.Bytes(), header[:uuid.Size]) {
					err = fmt.Errorf("XTLS Vision server responded unknown UUID: %s", uuid.FromBytesOrNil(header[:uuid.Size]))
					log.Errorln(err.Error())
					return err
				}
				header = header[uuid.Size:]
			}
			vc.readRemainingPadding = int(binary.BigEndian.Uint16(header[3:]))
			vc.readRemainingContent = int(binary.BigEndian.Uint16(header[1:]))
			vc.readLastCommand = header[0]
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
				_, err := buffer.ReadOnceFrom(vc.input)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						return err
					}
				}
				if vc.input.Len() == 0 {
					needReturn = true
					*vc.input = bytes.Reader{} // full reset
					vc.input = nil
				} else { // buffer is full
					return nil
				}
			}
			if vc.rawInput != nil {
				_, err := buffer.ReadOnceFrom(vc.rawInput)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						return err
					}
				}
				needReturn = true
				if vc.rawInput.Len() == 0 {
					*vc.rawInput = bytes.Buffer{} // full reset
					vc.rawInput = nil
				}
			}
			if vc.input == nil && vc.rawInput == nil {
				vc.readProcess = false
				vc.ExtendedReader = N.NewExtendedReader(vc.netConn)
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

func (vc *Conn) Write(p []byte) (int, error) {
	if vc.writeFilterApplicationData {
		return N.WriteBuffer(vc, buf.As(p))
	}
	return vc.ExtendedWriter.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) (err error) {
	if vc.writeFilterApplicationData {
		if buffer.IsEmpty() {
			ApplyPadding(buffer, commandPaddingContinue, &vc.writeOnceUserUUID, true) // we do a long padding to hide vless header
			return vc.ExtendedWriter.WriteBuffer(buffer)
		}

		vc.FilterTLS(buffer.Bytes())
		buffers := vc.ReshapeBuffer(buffer)
		applyPadding := true
		for i, buffer := range buffers {
			command := commandPaddingContinue
			if applyPadding {
				if vc.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) {
					command = commandPaddingEnd
					if vc.enableXTLS {
						command = commandPaddingDirect
						vc.writeDirect = true
					}
					vc.writeFilterApplicationData = false
					applyPadding = false
				} else if !vc.isTLS12orAbove && vc.packetsToFilter <= 1 {
					command = commandPaddingEnd
					vc.writeFilterApplicationData = false
					applyPadding = false
				}
				ApplyPadding(buffer, command, &vc.writeOnceUserUUID, vc.isTLS)
			}

			err = vc.ExtendedWriter.WriteBuffer(buffer)
			if err != nil {
				buf.ReleaseMulti(buffers[i:]) // release unwritten buffers
				return
			}
			if command == commandPaddingDirect {
				vc.ExtendedWriter = N.NewExtendedWriter(vc.netConn)
				log.Debugln("XTLS Vision direct write start")
				//time.Sleep(5 * time.Millisecond)
			}
		}
		return err
	}
	/*if vc.writeDirect {
		log.Debugln("XTLS Vision Direct write, payloadLen=%d", buffer.Len())
	}*/
	return vc.ExtendedWriter.WriteBuffer(buffer)
}

func (vc *Conn) FrontHeadroom() int {
	fontHeadroom := PaddingHeaderLen - uuid.Size
	if vc.readFilterUUID || vc.writeOnceUserUUID != nil {
		fontHeadroom = PaddingHeaderLen
	}
	if vc.writeFilterApplicationData { // The writer may be replaced, add the required value for vc.netConn
		if abs := N.CalculateFrontHeadroom(vc.netConn) - N.CalculateFrontHeadroom(vc.Conn); abs > 0 {
			fontHeadroom += abs
		}
	}
	return fontHeadroom
}

func (vc *Conn) RearHeadroom() int {
	rearHeadroom := 500 + 900
	if vc.writeFilterApplicationData { // The writer may be replaced, add the required value for vc.netConn
		if abs := N.CalculateRearHeadroom(vc.netConn) - N.CalculateRearHeadroom(vc.Conn); abs > 0 {
			rearHeadroom += abs
		}
	}
	return rearHeadroom
}

func (vc *Conn) NeedHandshake() bool {
	return vc.writeOnceUserUUID != nil
}

func (vc *Conn) NeedAdditionalReadDeadline() bool {
	return true
}

func (vc *Conn) Upstream() any {
	if vc.writeDirect ||
		vc.readLastCommand == commandPaddingDirect {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) ReaderPossiblyReplaceable() bool {
	return vc.readProcess
}

func (vc *Conn) ReaderReplaceable() bool {
	if !vc.readProcess &&
		vc.readLastCommand == commandPaddingDirect {
		return true
	}
	return false
}

func (vc *Conn) WriterPossiblyReplaceable() bool {
	return vc.writeFilterApplicationData
}

func (vc *Conn) WriterReplaceable() bool {
	if vc.writeDirect {
		return true
	}
	return false
}

func (vc *Conn) Close() error {
	if vc.ReaderReplaceable() || vc.WriterReplaceable() { // ignore send closeNotify alert in tls.Conn
		return vc.netConn.Close()
	}
	return vc.Conn.Close()
}
