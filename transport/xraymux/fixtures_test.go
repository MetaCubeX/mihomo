package xraymux

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Golden vectors are derived independently from Xray-core common/mux at
// revision 0ee156e75c9546a713f6c88c0bd14f5ff953c567. Keep these literals
// independent from the production encoder so they detect wire-format drift.
var referenceFrames = map[string]string{
	"domain-new-data":  "0014000101010101bb020b6578616d706c652e636f6d00026869",
	"domain-new-empty": "0014000101000101bb020b6578616d706c652e636f6d",
	"ipv4-new-empty":   "000c000201000100350101020304",
	"ipv6-new-empty":   "001800030100011f900300000000000000000000000000000001",
	"keep-data":        "00040001020100026f6b",
	"end":              "000400010300",
}

type referenceFrame struct {
	metaLen   uint16
	sessionID uint16
	status    byte
	option    byte
	metadata  []byte
	payload   []byte
}

func decodeReferenceFrame(raw []byte) (referenceFrame, error) {
	if len(raw) < 6 {
		return referenceFrame{}, io.ErrUnexpectedEOF
	}
	metaLen := binary.BigEndian.Uint16(raw[:2])
	if metaLen < 4 || int(metaLen)+2 > len(raw) {
		return referenceFrame{}, io.ErrUnexpectedEOF
	}
	meta := raw[2 : 2+metaLen]
	frame := referenceFrame{
		metaLen:   metaLen,
		sessionID: binary.BigEndian.Uint16(meta[:2]),
		status:    meta[2],
		option:    meta[3],
		metadata:  append([]byte(nil), meta[4:]...),
	}
	if frame.option&1 == 0 {
		if len(raw) != int(metaLen)+2 {
			return referenceFrame{}, errors.New("unexpected bytes after metadata-only frame")
		}
		return frame, nil
	}
	offset := 2 + int(metaLen)
	if len(raw) < offset+2 {
		return referenceFrame{}, io.ErrUnexpectedEOF
	}
	payloadLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	if len(raw) != offset+2+payloadLen {
		return referenceFrame{}, io.ErrUnexpectedEOF
	}
	frame.payload = append([]byte(nil), raw[offset+2:]...)
	return frame, nil
}

func TestReferenceFrameFixtures(t *testing.T) {
	tests := []struct {
		name      string
		status    byte
		option    byte
		sessionID uint16
		payload   string
	}{
		{name: "domain-new-data", status: 1, option: 1, sessionID: 1, payload: "hi"},
		{name: "domain-new-empty", status: 1, sessionID: 1},
		{name: "ipv4-new-empty", status: 1, sessionID: 2},
		{name: "ipv6-new-empty", status: 1, sessionID: 3},
		{name: "keep-data", status: 2, option: 1, sessionID: 1, payload: "ok"},
		{name: "end", status: 3, sessionID: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := hex.DecodeString(referenceFrames[tt.name])
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			frame, err := decodeReferenceFrame(raw)
			if err != nil {
				t.Fatalf("decode reference frame: %v", err)
			}
			if frame.status != tt.status || frame.option != tt.option || frame.sessionID != tt.sessionID {
				t.Fatalf("header = status %d option %d session %d", frame.status, frame.option, frame.sessionID)
			}
			if string(frame.payload) != tt.payload {
				t.Fatalf("payload = %q, want %q", frame.payload, tt.payload)
			}
		})
	}
}

type fakeTimer struct {
	mu      sync.Mutex
	stopped bool
	fn      func()
}

func (t *fakeTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive := !t.stopped
	t.stopped = true
	return wasActive
}

func (t *fakeTimer) fire() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.stopped = true
	fn := t.fn
	t.mu.Unlock()
	fn()
}

type fakeClock struct {
	mu     sync.Mutex
	timers []*fakeTimer
}

func (c *fakeClock) AfterFunc(_ time.Duration, fn func()) *fakeTimer {
	t := &fakeTimer{fn: fn}
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return t
}

func (c *fakeClock) FireAll() {
	c.mu.Lock()
	timers := append([]*fakeTimer(nil), c.timers...)
	c.timers = nil
	c.mu.Unlock()
	for _, timer := range timers {
		timer.fire()
	}
}

func (c *fakeClock) timerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes bytes.Buffer
	closed bool
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	_, _ = c.writes.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *recordingConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.writes.Bytes()...)
}
