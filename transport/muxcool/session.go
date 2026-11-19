package muxcool

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"

	M "github.com/metacubex/sing/common/metadata"
)

const (
	statusNew       byte = 1
	statusKeep      byte = 2
	statusEnd       byte = 3
	statusKeepAlive byte = 4

	optionData  byte = 1
	optionError byte = 2

	networkTCP byte = 1

	addrTypeIPv4   byte = 1
	addrTypeDomain byte = 2
	addrTypeIPv6   byte = 3

	// maxFrameData is the payload size used when splitting writes, same as xray.
	maxFrameData = 8 * 1024
	// streamBufferLimit is how many unread bytes a sub connection may hold
	// before the whole connection stops being read (Mux.Cool has no flow control).
	streamBufferLimit = 512 * 1024
)

var (
	errSessionFull   = errors.New("muxcool: session full")
	errSessionClosed = errors.New("muxcool: session closed")
	errRemoteError   = errors.New("muxcool: remote closed with error")
)

// session is one underlying connection carrying many sub connections.
type session struct {
	conn        net.Conn
	concurrency int

	writeAccess sync.Mutex

	access    sync.Mutex
	streams   map[uint16]*stream
	nextID    uint16
	opened    int
	closed    bool
	idleTimer *time.Timer

	recvOnce sync.Once
}

func newSession(conn net.Conn, concurrency int) *session {
	s := &session{
		conn:        conn,
		concurrency: concurrency,
		streams:     make(map[uint16]*stream),
		nextID:      1,
	}
	return s
}

func (s *session) isClosed() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.closed
}

// open creates a new sub connection and sends its New frame.
func (s *session) open(destination M.Socksaddr) (*stream, error) {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return nil, errSessionClosed
	}
	if len(s.streams) >= s.concurrency || s.opened >= maxSessionsPerConn {
		s.access.Unlock()
		return nil, errSessionFull
	}
	id := s.nextID
	s.nextID++
	s.opened++
	st := newStream(s, id)
	s.streams[id] = st
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.access.Unlock()

	if err := s.writeNewFrame(id, destination); err != nil {
		s.close(err)
		return nil, err
	}
	// the proxy request is sent together with the first frame, only start
	// reading the response after that.
	s.recvOnce.Do(func() { go s.recvLoop() })
	return st, nil
}

func (s *session) writeNewFrame(id uint16, destination M.Socksaddr) error {
	var addr []byte
	var addrType byte
	if destination.IsFqdn() {
		if len(destination.Fqdn) > 255 {
			return errors.New("muxcool: domain name too long")
		}
		addrType = addrTypeDomain
		addr = append([]byte{byte(len(destination.Fqdn))}, destination.Fqdn...)
	} else if ip := destination.Addr.Unmap(); ip.Is4() {
		addrType = addrTypeIPv4
		addr = ip.AsSlice()
	} else if ip.Is6() {
		addrType = addrTypeIPv6
		addr = ip.AsSlice()
	} else {
		return errors.New("muxcool: invalid destination")
	}

	metaLen := 4 + 1 + 2 + 1 + len(addr)
	frame := make([]byte, 0, 2+metaLen)
	frame = binary.BigEndian.AppendUint16(frame, uint16(metaLen))
	frame = binary.BigEndian.AppendUint16(frame, id)
	frame = append(frame, statusNew, 0, networkTCP)
	frame = binary.BigEndian.AppendUint16(frame, destination.Port)
	frame = append(frame, addrType)
	frame = append(frame, addr...)

	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	_, err := s.conn.Write(frame)
	return err
}

func (s *session) writeData(id uint16, p []byte) (n int, err error) {
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrameData {
			chunk = chunk[:maxFrameData]
		}
		frame := pool.Get(8 + len(chunk))
		binary.BigEndian.PutUint16(frame, 4)
		binary.BigEndian.PutUint16(frame[2:], id)
		frame[4] = statusKeep
		frame[5] = optionData
		binary.BigEndian.PutUint16(frame[6:], uint16(len(chunk)))
		copy(frame[8:], chunk)

		s.writeAccess.Lock()
		_, err = s.conn.Write(frame)
		s.writeAccess.Unlock()
		_ = pool.Put(frame)
		if err != nil {
			s.close(err)
			return n, err
		}
		n += len(chunk)
		p = p[len(chunk):]
	}
	return n, nil
}

func (s *session) writeEnd(id uint16, hasError bool) {
	frame := [6]byte{0, 4, byte(id >> 8), byte(id), statusEnd, 0}
	if hasError {
		frame[5] = optionError
	}
	s.writeAccess.Lock()
	_, err := s.conn.Write(frame[:])
	s.writeAccess.Unlock()
	if err != nil {
		s.close(err)
	}
}

// remove forgets a sub connection, reports whether it was still registered.
func (s *session) remove(id uint16) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if _, ok := s.streams[id]; !ok {
		return false
	}
	delete(s.streams, id)
	if len(s.streams) == 0 && !s.closed {
		if s.opened >= maxSessionsPerConn {
			// can't be used anymore
			go s.close(errSessionClosed)
		} else {
			s.idleTimer = time.AfterFunc(idleTimeout, s.closeIfIdle)
		}
	}
	return true
}

func (s *session) closeIfIdle() {
	s.access.Lock()
	idle := len(s.streams) == 0
	if idle {
		// refuse new sub connections from now on
		s.opened = maxSessionsPerConn
	}
	s.access.Unlock()
	if idle {
		s.close(errSessionClosed)
	}
}

func (s *session) close(err error) {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return
	}
	s.closed = true
	streams := s.streams
	s.streams = make(map[uint16]*stream)
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.access.Unlock()

	_ = s.conn.Close()
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	for _, st := range streams {
		st.closeWithError(err)
	}
}

func (s *session) recvLoop() {
	reader := bufio.NewReaderSize(s.conn, 16*1024)
	var header [2]byte
	var meta [512]byte
	for {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			s.close(err)
			return
		}
		metaLen := int(binary.BigEndian.Uint16(header[:]))
		if metaLen < 4 || metaLen > len(meta) {
			s.close(errors.New("muxcool: invalid frame metadata length"))
			return
		}
		if _, err := io.ReadFull(reader, meta[:metaLen]); err != nil {
			s.close(err)
			return
		}
		id := binary.BigEndian.Uint16(meta[:2])
		status := meta[2]
		option := meta[3]

		var st *stream
		switch status {
		case statusKeep:
			s.access.Lock()
			st = s.streams[id]
			s.access.Unlock()
			// an unknown sub connection is one we already closed (the End frame
			// is on its way) or the remote peer ended, its data is just dropped.
		case statusEnd:
			s.access.Lock()
			ended := s.streams[id]
			s.access.Unlock()
			if ended != nil {
				s.remove(id)
				if option&optionError != 0 {
					ended.closeWithError(errRemoteError)
				} else {
					ended.closeWithError(io.EOF)
				}
			}
		case statusNew, statusKeepAlive:
			// the server never opens sub connections to us, just drop the payload
		default:
			s.close(errors.New("muxcool: unknown frame status"))
			return
		}

		if option&optionData == 0 {
			continue
		}
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			s.close(err)
			return
		}
		dataLen := int(binary.BigEndian.Uint16(header[:]))
		if dataLen == 0 {
			continue
		}
		if st == nil {
			if _, err := reader.Discard(dataLen); err != nil {
				s.close(err)
				return
			}
			continue
		}
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(reader, data); err != nil {
			s.close(err)
			return
		}
		st.push(data)
	}
}
