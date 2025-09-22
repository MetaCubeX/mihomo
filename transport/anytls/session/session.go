package session

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamId   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	synDone     func()
	synDoneLock sync.Mutex

	// pool
	seq       uint64
	idleSince time.Time
	padding   *atomic.Pointer[padding.PaddingFactory]

	peerVersion byte

	// client
	isClient    bool
	sendPadding bool
	buffering   bool
	buffer      []byte
	pktCounter  atomic.Uint32

	// server
	onNewStream func(stream *Stream)
}

func NewClientSession(conn net.Conn, _padding *atomic.Pointer[padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		isClient:    true,
		sendPadding: true,
		padding:     _padding,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.Pointer[padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func (s *Session) Run() {
	if !s.isClient {
		s.recvLoop()
		return
	}

	settings := util.StringMap{
		"v":           "2",
		"client":      "mihomo/" + constant.Version,
		"padding-md5": s.padding.Load().Md5,
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.buffering = true
	s.writeControlFrame(f)

	go s.recvLoop()
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close is used to close the session and all streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		s.streamLock.Lock()
		for _, stream := range s.streams {
			stream.closeLocally()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
	}
}

// OpenStream is used to create a new stream for CLIENT
func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamId.Add(1)
	stream := newStream(sid, s)

	if sid >= 2 && s.peerVersion >= 2 {
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
		}
		s.synDone = util.NewDeadlineWatcher(time.Second*3, func() {
			s.Close()
		})
		s.synDoneLock.Unlock()
	}

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		return nil, err
	}

	s.buffering = false // proxy Write it's SocksAddr to flush the buffer

	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	select {
	case <-s.die:
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
		return stream, nil
	}
}

func (s *Session) recvLoop() error {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[BUG] %v %s", r, string(debug.Stack()))
		}
	}()
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
		// read header first
		if _, err := io.ReadFull(s.conn, hdr[:]); err == nil {
			sid := hdr.StreamID()
			switch hdr.Cmd() {
			case cmdPSH:
				if hdr.Length() > 0 {
					buffer := pool.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err == nil {
						s.streamLock.RLock()
						stream, ok := s.streams[sid]
						s.streamLock.RUnlock()
						if ok {
							stream.pipeW.Write(buffer)
						}
						pool.Put(buffer)
					} else {
						pool.Put(buffer)
						return err
					}
				}
			case cmdSYN: // should be server only
				if !s.isClient && !receivedSettingsFromClient {
					f := newFrame(cmdAlert, 0)
					f.data = []byte("client did not send its settings")
					s.writeControlFrame(f)
					return nil
				}
				s.streamLock.Lock()
				if _, ok := s.streams[sid]; !ok {
					stream := newStream(sid, s)
					s.streams[sid] = stream
					go func() {
						if s.onNewStream != nil {
							s.onNewStream(stream)
						} else {
							stream.Close()
						}
					}()
				}
				s.streamLock.Unlock()
			case cmdSYNACK: // should be client only
				s.synDoneLock.Lock()
				if s.synDone != nil {
					s.synDone()
					s.synDone = nil
				}
				s.synDoneLock.Unlock()
				if hdr.Length() > 0 {
					buffer := pool.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						pool.Put(buffer)
						return err
					}
					// report error
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok {
						stream.closeWithError(fmt.Errorf("remote: %s", string(buffer)))
					}
					pool.Put(buffer)
				}
			case cmdFIN:
				s.streamLock.Lock()
				stream, ok := s.streams[sid]
				delete(s.streams, sid)
				s.streamLock.Unlock()
				if ok {
					stream.closeLocally()
				}
			case cmdWaste:
				if hdr.Length() > 0 {
					buffer := pool.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						pool.Put(buffer)
						return err
					}
					pool.Put(buffer)
				}
			case cmdSettings:
				if hdr.Length() > 0 {
					buffer := pool.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						pool.Put(buffer)
						return err
					}
					if !s.isClient {
						receivedSettingsFromClient = true
						m := util.StringMapFromBytes(buffer)
						paddingF := s.padding.Load()
						if m["padding-md5"] != paddingF.Md5 {
							f := newFrame(cmdUpdatePaddingScheme, 0)
							f.data = paddingF.RawScheme
							_, err = s.writeControlFrame(f)
							if err != nil {
								pool.Put(buffer)
								return err
							}
						}
						// check client's version
						if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
							s.peerVersion = byte(v)
							// send cmdServerSettings
							f := newFrame(cmdServerSettings, 0)
							f.data = util.StringMap{
								"v": "2",
							}.ToBytes()
							_, err = s.writeControlFrame(f)
							if err != nil {
								pool.Put(buffer)
								return err
							}
						}
					}
					pool.Put(buffer)
				}
			case cmdAlert:
				if hdr.Length() > 0 {
					buffer := pool.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						pool.Put(buffer)
						return err
					}
					if s.isClient {
						log.Errorln("[Alert from server] %s", string(buffer))
					}
					pool.Put(buffer)
					return nil
				}
			case cmdUpdatePaddingScheme:
				if hdr.Length() > 0 {
					// `rawScheme` Do not use buffer to prevent subsequent misuse
					rawScheme := make([]byte, int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, rawScheme); err != nil {
						return err
					}
					if s.isClient {
						if padding.UpdatePaddingScheme(rawScheme, s.padding) {
							log.Debugln("[Update padding succeed] %x\n", md5.Sum(rawScheme))
						} else {
							log.Warnln("[Update padding failed] %x\n", md5.Sum(rawScheme))
						}
					}
				}
			case cmdHeartRequest:
				if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
					return err
				}
			case cmdHeartResponse:
				// Active keepalive checking is not implemented yet
				break
			case cmdServerSettings:
				if hdr.Length() > 0 {
					buffer := pool.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						pool.Put(buffer)
						return err
					}
					if s.isClient {
						// check server's version
						m := util.StringMapFromBytes(buffer)
						if v, err := strconv.Atoi(m["v"]); err == nil {
							s.peerVersion = byte(v)
						}
					}
					pool.Put(buffer)
				}
			default:
				// I don't know what command it is (can't have data)
			}
		} else {
			return err
		}
	}
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(cmdPSH)
	binary.BigEndian.PutUint32(buffer.Extend(4), sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(data)
	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		return 0, err
	}

	return dataLen, nil
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	s.conn.SetWriteDeadline(time.Now().Add(time.Second * 5))

	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	s.conn.SetWriteDeadline(time.Time{})

	return dataLen, nil
}

func (s *Session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.buffering {
		s.buffer = append(s.buffer, b...)
		return len(b), nil
	} else if len(s.buffer) > 0 {
		b = append(s.buffer, b...)
		s.buffer = nil
	}

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == padding.CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = append(b, padding...)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.conn.Write(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.conn.Write(b)
}
