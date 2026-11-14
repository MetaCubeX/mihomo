package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"

	"github.com/gofrs/uuid/v5"
)

var (
	_ N.ExtendedConn = (*Conn)(nil)
)

const (
	modePadding uint32 = iota
	modeStream
	modeDirect
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

	// Serialize each direction independently. Neither lock is needed by Close
	// or by the metadata methods used by sing's buffer allocation/unwrapping.
	readMu  sync.Mutex
	writeMu sync.Mutex

	// FilterTLS is called by both directions. Its state and the writer's
	// padding decisions must be read/written as a coherent snapshot.
	filterMu sync.Mutex

	// Publish completed transitions without exposing direction-owned fields.
	readMode      atomic.Uint32
	writeMode     atomic.Uint32
	handshakeDone atomic.Bool
	closed        atomic.Bool

	// Once either peer begins a direct transition, Close must not send a TLS
	// close_notify. Coordinate this decision with transitions, not blocking I/O.
	closeMu   sync.Mutex
	direct    bool
	closeOnce sync.Once
	closeErr  error

	packetsToFilter      int
	isTLS                bool
	isTLS12orAbove       bool
	enableXTLS           bool
	cipher               uint16
	remainingServerHello uint16
	readRemainingBuffer  *buf.Buffer
	readRemainingContent int
	readRemainingPadding int
	readFilterUUID       bool
	readLastCommand      byte
	writeOnceUserUUID    []byte
}

func (vc *Conn) Read(b []byte) (int, error) {
	vc.readMu.Lock()
	defer vc.readMu.Unlock()
	if vc.closed.Load() {
		return 0, net.ErrClosed
	}
	if vc.readMode.Load() == modePadding {
		buffer := buf.With(b)
		err := vc.readBuffer(buffer)
		if unsafe.SliceData(buffer.Bytes()) != unsafe.SliceData(b) { // buffer.Bytes() not at the beginning of b
			copy(b, buffer.Bytes())
		}
		return buffer.Len(), err
	}
	return vc.ExtendedReader.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	vc.readMu.Lock()
	defer vc.readMu.Unlock()
	if vc.closed.Load() {
		return net.ErrClosed
	}
	return vc.readBuffer(buffer)
}

// readBuffer is also used recursively while readMu is held.
func (vc *Conn) readBuffer(buffer *buf.Buffer) error {
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
			innerErr := vc.readBuffer(buffer) // back to top but not losing err
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
	if vc.readMode.Load() == modePadding {
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
			if vc.readLastCommand == commandPaddingDirect {
				if err := vc.beginDirect(); err != nil {
					return err
				}
			}
			log.Debugln("XTLS Vision read padding: command=%d, payloadLen=%d, paddingLen=%d",
				vc.readLastCommand, vc.readRemainingContent, vc.readRemainingPadding)
			return vc.readBuffer(buffer)
			//}
		case commandPaddingEnd:
			vc.readMode.Store(modeStream)
			return vc.readBuffer(buffer)
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
				vc.ExtendedReader = N.NewExtendedReader(vc.netConn)
				vc.readMode.Store(modeDirect)
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
	if vc.writeMode.Load() == modePadding {
		return N.WriteBuffer(vc, buf.As(p))
	}
	vc.writeMu.Lock()
	defer vc.writeMu.Unlock()
	if vc.closed.Load() {
		return 0, net.ErrClosed
	}
	return vc.ExtendedWriter.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) (err error) {
	vc.writeMu.Lock()
	defer vc.writeMu.Unlock()
	if vc.closed.Load() {
		buffer.Release()
		return net.ErrClosed
	}
	if vc.writeMode.Load() == modePadding {
		nextMode := modePadding
		// Do not let an unwrapped writer overtake the remaining buffers from
		// this call after its first buffer carries the direct command.
		defer func() { vc.writeMode.Store(nextMode) }()
		if buffer.IsEmpty() {
			ApplyPadding(buffer, commandPaddingContinue, &vc.writeOnceUserUUID, true) // we do a long padding to hide vless header
			err = vc.ExtendedWriter.WriteBuffer(buffer)
			if err == nil {
				vc.handshakeDone.Store(true)
			}
			return err
		}

		vc.FilterTLS(buffer.Bytes())
		buffers := vc.ReshapeBuffer(buffer)
		applyPadding := true
		for i, buffer := range buffers {
			command := commandPaddingContinue
			if applyPadding {
				vc.filterMu.Lock()
				if vc.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) {
					command = commandPaddingEnd
					if vc.enableXTLS {
						command = commandPaddingDirect
					}
					applyPadding = false
				} else if !vc.isTLS12orAbove && vc.packetsToFilter <= 1 {
					command = commandPaddingEnd
					applyPadding = false
				}
				paddingTLS := vc.isTLS
				vc.filterMu.Unlock()
				if command == commandPaddingDirect {
					if err = vc.beginDirect(); err != nil {
						buf.ReleaseMulti(buffers[i:])
						return err
					}
				}
				ApplyPadding(buffer, command, &vc.writeOnceUserUUID, paddingTLS)
			}

			err = vc.ExtendedWriter.WriteBuffer(buffer)
			if err != nil {
				buf.ReleaseMulti(buffers[i:]) // release unwritten buffers
				return
			}
			vc.handshakeDone.Store(true)
			if command == commandPaddingDirect {
				vc.ExtendedWriter = N.NewExtendedWriter(vc.netConn)
				nextMode = modeDirect
				log.Debugln("XTLS Vision direct write start")
				//time.Sleep(5 * time.Millisecond)
			} else if command == commandPaddingEnd {
				nextMode = modeStream
			}
		}
		return err
	}
	return vc.ExtendedWriter.WriteBuffer(buffer)
}

func (vc *Conn) FrontHeadroom() int {
	if vc.writeMode.Load() != modePadding {
		return 0
	}
	// Reserve the first frame's UUID and the possible direct writer's headroom
	// even if the write mode changes between allocation and WriteBuffer.
	return PaddingHeaderLen + N.CalculateFrontHeadroom(vc.netConn)
}

func (vc *Conn) RearHeadroom() int {
	if vc.writeMode.Load() != modePadding {
		return 0
	}
	return 500 + 900 + N.CalculateRearHeadroom(vc.netConn)
}

func (vc *Conn) NeedHandshake() bool {
	return !vc.handshakeDone.Load()
}

func (vc *Conn) NeedAdditionalReadDeadline() bool {
	return true
}

func (vc *Conn) Upstream() any {
	if vc.writeMode.Load() == modeDirect || vc.readMode.Load() == modeDirect {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) UpstreamReader() any {
	if vc.readMode.Load() == modeDirect {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) UpstreamWriter() any {
	if vc.writeMode.Load() == modeDirect {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) ReaderPossiblyReplaceable() bool {
	return vc.readMode.Load() == modePadding
}

func (vc *Conn) ReaderReplaceable() bool {
	return vc.readMode.Load() == modeDirect
}

func (vc *Conn) WriterPossiblyReplaceable() bool {
	return vc.writeMode.Load() == modePadding
}

func (vc *Conn) WriterReplaceable() bool {
	return vc.writeMode.Load() == modeDirect
}

func (vc *Conn) beginDirect() error {
	vc.closeMu.Lock()
	defer vc.closeMu.Unlock()
	if vc.closed.Load() {
		return net.ErrClosed
	}
	vc.direct = true
	return nil
}

func (vc *Conn) Close() error {
	vc.closeOnce.Do(func() {
		vc.closeMu.Lock()
		vc.closed.Store(true)
		direct := vc.direct
		vc.closeMu.Unlock()
		if direct { // ignore send closeNotify alert in tls.Conn
			vc.closeErr = vc.netConn.Close()
		} else {
			vc.closeErr = vc.Conn.Close()
		}
	})
	return vc.closeErr
}
