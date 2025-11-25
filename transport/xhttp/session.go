package xhttp

import (
	"container/heap"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

type Packet struct {
	Payload []byte
	Reader  io.ReadCloser
	Seq     uint64
}

type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}

type uploadQueue struct {
	pushedPackets chan Packet
	heap          *uploadHeap
	nextSeq       uint64
	maxPackets    int
	closed        atomic.Bool
	mu            sync.Mutex
}

func newUploadQueue(maxPackets int) *uploadQueue {
	h := &uploadHeap{}
	heap.Init(h)
	return &uploadQueue{
		pushedPackets: make(chan Packet, DefaultPacketChannelSize),
		heap:          h,
		nextSeq:       0,
		maxPackets:    maxPackets,
	}
}

func (uq *uploadQueue) Push(packet Packet) error {
	if uq.closed.Load() {
		return io.ErrClosedPipe
	}
	select {
	case uq.pushedPackets <- packet:
		return nil
	default:
		return io.ErrShortBuffer
	}
}

func (uq *uploadQueue) Read(p []byte) (n int, err error) {
	uq.mu.Lock()
	defer uq.mu.Unlock()

	for {
		if uq.heap.Len() > 0 {
			top := (*uq.heap)[0]
			if top.Seq == uq.nextSeq {
				heap.Pop(uq.heap)
				uq.nextSeq++

				if top.Payload != nil {
					n = copy(p, top.Payload)
					if n < len(top.Payload) {
						return n, io.ErrShortBuffer
					}
					return n, nil
				} else if top.Reader != nil {
					return top.Reader.Read(p)
				}
			}
		}

		if uq.closed.Load() {
			if uq.heap.Len() == 0 {
				return 0, io.EOF
			}
			return 0, io.ErrUnexpectedEOF
		}

		timer := time.NewTimer(DefaultPollInterval)
		uq.mu.Unlock()
		select {
		case packet := <-uq.pushedPackets:
			timer.Stop()
			uq.mu.Lock()
			if uq.heap.Len() >= uq.maxPackets {
				return 0, io.ErrShortBuffer
			}
			heap.Push(uq.heap, packet)
			continue
		case <-timer.C:
			uq.mu.Lock()
			if uq.heap.Len() > 0 {
				continue
			}
			return 0, io.ErrNoProgress
		}
	}
}

func (uq *uploadQueue) Close() error {
	if uq.closed.CompareAndSwap(false, true) {
		close(uq.pushedPackets)
		uq.mu.Lock()
		defer uq.mu.Unlock()
		for uq.heap.Len() > 0 {
			packet := heap.Pop(uq.heap).(Packet)
			if packet.Reader != nil {
				packet.Reader.Close()
			}
		}
	}
	return nil
}

type httpSession struct {
	sessionId     string
	uploadQueue   *uploadQueue
	downloadQueue chan []byte
	proxyConn     net.Conn
	mode          string
	created       time.Time
	expiry        time.Time
	closed        atomic.Bool
	tunnelStarted atomic.Bool
	mu            sync.Mutex
}

func newHTTPSession(sessionId string, maxPackets int) *httpSession {
	return &httpSession{
		sessionId:     sessionId,
		uploadQueue:   newUploadQueue(maxPackets),
		downloadQueue: make(chan []byte, DefaultPacketChannelSize),
		created:       time.Now(),
	}
}

func (s *httpSession) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed.Load() {
		return nil
	}
	s.closed.Store(true)

	if s.uploadQueue != nil {
		s.uploadQueue.Close()
	}

	if s.downloadQueue != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Warnln("xhttp: panic closing downloadQueue: %v", r)
				}
			}()
			close(s.downloadQueue)
		}()
	}

	if s.proxyConn != nil {
		s.proxyConn.Close()
	}

	log.Debugln("xhttp: session %s closed", s.sessionId)
	return nil
}

func (s *httpSession) isExpired(now time.Time) bool {
	return !s.expiry.IsZero() && now.After(s.expiry)
}

func (s *httpSession) startTunnel(remoteAddr, localAddr net.Addr, handleFunc func(net.Conn)) bool {
	if !s.tunnelStarted.CompareAndSwap(false, true) {
		return false
	}

	conn := newXHTTPConn(s, remoteAddr, localAddr)
	s.mu.Lock()
	s.proxyConn = conn
	s.mu.Unlock()

	go handleFunc(conn)
	return true
}

type xhttpConn struct {
	session    *httpSession
	remoteAddr net.Addr
	localAddr  net.Addr
	readBuf    []byte
}

func newXHTTPConn(session *httpSession, remoteAddr, localAddr net.Addr) *xhttpConn {
	return &xhttpConn{
		session:    session,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}
}

func (c *xhttpConn) Read(b []byte) (n int, err error) {
	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	n, err = c.session.uploadQueue.Read(buf)
	if n > 0 {
		copied := copy(b, buf[:n])
		if copied < n {
			c.readBuf = make([]byte, n-copied)
			copy(c.readBuf, buf[copied:n])
		}
		return copied, nil
	}
	return 0, err
}

func (c *xhttpConn) Write(b []byte) (n int, err error) {
	if c.session.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	if len(b) > DefaultMaxWriteSize {
		return 0, io.ErrShortWrite
	}

	data := make([]byte, len(b))
	copy(data, b)

	select {
	case c.session.downloadQueue <- data:
		return len(b), nil
	default:
		return 0, io.ErrShortBuffer
	}
}

func (c *xhttpConn) Close() error {
	return c.session.close()
}

func (c *xhttpConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *xhttpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *xhttpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *xhttpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *xhttpConn) SetWriteDeadline(t time.Time) error {
	return nil
}
