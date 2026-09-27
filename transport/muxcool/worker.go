package muxcool

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errWorkerUnavailable = errors.New("mux.cool carrier is unavailable")

type carrierWorker struct {
	conn        net.Conn
	maxActive   int
	maxLifetime int
	onClosed    func(*carrierWorker)
	onIdle      func(*carrierWorker)
	onAvailable func(*carrierWorker)

	writeMu     sync.Mutex
	writeBuffer []byte
	mu          sync.Mutex
	sessions    map[uint16]workerSession
	nextID      uint32
	lifetime    int
	draining    bool
	closed      bool
	closedFast  atomic.Bool
	closeErr    error
	closeOnce   sync.Once
}

func newCarrierWorker(conn net.Conn, maxActive, maxLifetime int, onClosed func(*carrierWorker)) *carrierWorker {
	w := &carrierWorker{
		conn:        conn,
		maxActive:   maxActive,
		maxLifetime: maxLifetime,
		onClosed:    onClosed,
		sessions:    make(map[uint16]workerSession),
	}
	go w.readLoop()
	return w
}

func (w *carrierWorker) openSession(
	ctx context.Context,
	destination string,
	port uint16,
	firstPayloadTimeout time.Duration,
) (net.Conn, error) {
	w.mu.Lock()
	id, err := w.allocateIDLocked()
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	conn, logicalSession := makeSession(w, id, destination, port)
	w.sessions[id] = logicalSession
	w.mu.Unlock()

	logicalSession.start(ctx, firstPayloadTimeout)
	return conn, nil
}

func (w *carrierWorker) openPacketSession(
	destination string,
	port uint16,
	globalID [8]byte,
) (net.PacketConn, error) {
	w.mu.Lock()
	id, err := w.allocateIDLocked()
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	logicalSession := makePacketSession(w, id, destination, port, globalID)
	w.sessions[id] = logicalSession
	w.mu.Unlock()

	return logicalSession, nil
}

func (w *carrierWorker) allocateIDLocked() (uint16, error) {
	if !w.availableLocked() {
		err := w.closeErr
		if err == nil {
			err = errWorkerUnavailable
		}
		return 0, err
	}
	w.nextID++
	w.lifetime++
	if w.lifetime >= w.maxLifetime || w.nextID == uint32(^uint16(0)) {
		w.draining = true
	}
	return uint16(w.nextID), nil
}

func (w *carrierWorker) availableLocked() bool {
	return !w.closed && !w.draining && len(w.sessions) < w.maxActive && w.lifetime < w.maxLifetime && w.nextID < uint32(^uint16(0))
}

func (w *carrierWorker) activeSessions() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.sessions)
}

func (w *carrierWorker) writeFrame(frame Frame) error {
	w.writeMu.Lock()
	raw, err := encodeFrame(w.writeBuffer, frame)
	if err != nil {
		w.writeMu.Unlock()
		return err
	}
	w.writeBuffer = raw[:0]
	if w.closedFast.Load() {
		w.mu.Lock()
		err = w.closeErr
		if err == nil {
			err = net.ErrClosed
		}
		w.mu.Unlock()
		w.writeMu.Unlock()
		return err
	}
	err = writeFull(w.conn, raw)
	w.writeMu.Unlock()
	if err != nil {
		// Closing may re-enter writeFrame through a session's End path. Defer the
		// fan-out until this call has returned to keep close paths acyclic.
		go w.close(err)
	}
	return err
}

func (w *carrierWorker) removeSession(id uint16) {
	w.mu.Lock()
	wasFull := len(w.sessions) >= w.maxActive
	delete(w.sessions, id)
	isIdle := len(w.sessions) == 0
	shouldClose := w.draining && isIdle
	isAvailable := w.availableLocked()
	w.mu.Unlock()
	if shouldClose {
		w.close(nil)
		return
	}
	if wasFull && isAvailable && w.onAvailable != nil {
		w.onAvailable(w)
	}
	if isIdle && w.onIdle != nil {
		w.onIdle(w)
	}
}

func (w *carrierWorker) readLoop() {
	metadataBuffer := make([]byte, MaxMetadataSize)
	for {
		frame, err := decodeFramePooled(w.conn, metadataBuffer)
		if err != nil {
			w.close(err)
			return
		}
		if frame.Status == StatusKeepAlive {
			frame.releasePayload()
			continue
		}

		w.mu.Lock()
		logicalSession := w.sessions[frame.SessionID]
		w.mu.Unlock()
		if logicalSession == nil {
			frame.releasePayload()
			if frame.Status == StatusEnd {
				continue
			}
			if err := w.writeFrame(Frame{SessionID: frame.SessionID, Status: StatusEnd}); err != nil {
				return
			}
			continue
		}

		if err := logicalSession.deliverDecodedFrame(frame); err != nil && !errors.Is(err, net.ErrClosed) {
			w.close(err)
			return
		}
	}
}

func (w *carrierWorker) close(cause error) {
	w.closeOnce.Do(func() {
		if cause == nil {
			cause = net.ErrClosed
		}

		w.closedFast.Store(true)
		w.mu.Lock()
		w.closed = true
		w.closeErr = cause
		sessions := make([]workerSession, 0, len(w.sessions))
		for _, logicalSession := range w.sessions {
			sessions = append(sessions, logicalSession)
		}
		w.sessions = nil
		w.mu.Unlock()

		_ = w.conn.Close()
		for _, logicalSession := range sessions {
			logicalSession.closeCarrier(cause)
		}
		if w.onClosed != nil {
			w.onClosed(w)
		}
	})
}
