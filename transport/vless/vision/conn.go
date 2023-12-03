package vision

import (
	"bytes"
	"crypto/subtle"
	gotls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"

	"github.com/gofrs/uuid/v5"
	utls "github.com/sagernet/utls"
)

var (
	_ N.ExtendedConn = (*Conn)(nil)
)

type Conn struct {
	net.Conn
	N.ExtendedReader
	N.ExtendedWriter
	upstream net.Conn
	userUUID *uuid.UUID

	tlsConn  net.Conn
	input    *bytes.Reader
	rawInput *bytes.Buffer

	needHandshake              bool
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
	if vc.readProcess {
		buffer := buf.With(b)
		err := vc.ReadBuffer(buffer)
		return buffer.Len(), err
	}
	return vc.ExtendedReader.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
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
			if need := headerUUIDLen + PaddingHeaderLen - uuid.Size; buffer.FreeLen() < need {
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
				if subtle.ConstantTimeCompare(vc.userUUID.Bytes(), header[:uuid.Size]) != 1 {
					err = fmt.Errorf("XTLS Vision server responded unknown UUID: %s",
						uuid.FromBytesOrNil(header[:uuid.Size]).String())
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

func (vc *Conn) Write(p []byte) (int, error) {
	if vc.writeFilterApplicationData {
		buffer := buf.New()
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

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) (err error) {
	if vc.needHandshake {
		vc.needHandshake = false
		if buffer.IsEmpty() {
			ApplyPadding(buffer, commandPaddingContinue, vc.userUUID, false)
		} else {
			vc.FilterTLS(buffer.Bytes())
			ApplyPadding(buffer, commandPaddingContinue, vc.userUUID, vc.isTLS)
		}
		err = vc.ExtendedWriter.WriteBuffer(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		switch underlying := vc.tlsConn.(type) {
		case *gotls.Conn:
			if underlying.ConnectionState().Version != gotls.VersionTLS13 {
				buffer.Release()
				return ErrNotTLS13
			}
		case *utls.UConn:
			if underlying.ConnectionState().Version != utls.VersionTLS13 {
				buffer.Release()
				return ErrNotTLS13
			}
		}
		vc.tlsConn = nil
		return nil
	}

	if vc.writeFilterApplicationData {
		buffer2 := ReshapeBuffer(buffer)
		defer buffer2.Release()
		vc.FilterTLS(buffer.Bytes())
		command := commandPaddingContinue
		if !vc.isTLS {
			command = commandPaddingEnd

			// disable XTLS
			//vc.readProcess = false
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
		ApplyPadding(buffer, command, nil, vc.isTLS)
		err = vc.ExtendedWriter.WriteBuffer(buffer)
		if err != nil {
			return err
		}
		if vc.writeDirect {
			vc.ExtendedWriter = N.NewExtendedWriter(vc.Conn)
			log.Debugln("XTLS Vision direct write start")
			//time.Sleep(5 * time.Millisecond)
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
			ApplyPadding(buffer2, command, nil, vc.isTLS)
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

func (vc *Conn) FrontHeadroom() int {
	if vc.readFilterUUID {
		return PaddingHeaderLen
	}
	return PaddingHeaderLen - uuid.Size
}

func (vc *Conn) NeedHandshake() bool {
	return vc.needHandshake
}

func (vc *Conn) Upstream() any {
	if vc.writeDirect ||
		vc.readLastCommand == commandPaddingDirect {
		return vc.Conn
	}
	return vc.upstream
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
