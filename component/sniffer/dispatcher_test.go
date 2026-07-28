package sniffer

// Tests for the Dispatcher's data-feeding loop: how much data a sniffer is
// handed, when it is asked again, and when the dispatcher gives up. Protocol
// parsing itself (a complete buffer in, a domain out) belongs in sniff_test.go.

import (
	"io"
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"

	"github.com/stretchr/testify/assert"
)

// chunkedConn hands out one chunk per Read, so a sniffer only ever sees the
// bytes that have "arrived". It models a request spanning several TCP segments,
// and reports EOF once they run out.
//
// Read deadlines are armed for real: the deadline is a watchdog that must never
// fire, because sniffing should reach a verdict from the data it is given rather
// than sit and wait. A read that would block without any deadline set fails the
// test too, since that is a conn stuck forever.
type chunkedConn struct {
	net.Conn
	t        *testing.T
	chunks   [][]byte
	deadline time.Time
	timer    *time.Timer
}

func (c *chunkedConn) Read(b []byte) (int, error) {
	if len(c.chunks) > 0 {
		chunk := c.chunks[0]
		c.chunks = c.chunks[1:]
		return copy(b, chunk), nil
	}
	if c.deadline.IsZero() {
		c.t.Error("read would block with no read deadline set")
	}
	return 0, io.EOF
}

func (c *chunkedConn) SetReadDeadline(deadline time.Time) error {
	c.stopTimer()
	c.deadline = deadline
	if !deadline.IsZero() {
		c.timer = time.AfterFunc(time.Until(deadline), func() {
			c.t.Error("read deadline expired: sniffing waited instead of deciding")
		})
	}
	return nil
}

func (c *chunkedConn) stopTimer() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

func (c *chunkedConn) Write(b []byte) (int, error)    { return len(b), nil }
func (c *chunkedConn) Close() error                   { return nil }
func (*chunkedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*chunkedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*chunkedConn) SetDeadline(time.Time) error      { return nil }
func (*chunkedConn) SetWriteDeadline(time.Time) error { return nil }

// stubSniffer records the size of every buffer it is handed and replies with a
// scripted answer, so the feeding loop can be tested without any real protocol.
type stubSniffer struct {
	seen  []int
	reply func(data []byte) (string, error)
}

var _ sniffer.Sniffer = (*stubSniffer)(nil)

func (*stubSniffer) SupportNetwork() C.NetWork { return C.TCP }
func (*stubSniffer) Protocol() string          { return "stub" }
func (*stubSniffer) SupportPort(uint16) bool   { return true }

func (s *stubSniffer) SniffData(b []byte) (string, error) {
	s.seen = append(s.seen, len(b))
	return s.reply(b)
}

func needAtLeast(n int) error {
	return &errNeedAtLeastData{length: n, err: ErrNoClue}
}

func TestDispatcherFeedLoop(t *testing.T) {
	segment := []byte("0123456789")
	threeSegments := [][]byte{segment, segment, segment}

	tests := []struct {
		name    string
		chunks  [][]byte
		reply   func(data []byte) (string, error)
		host    string
		wantErr bool
		// size of each buffer handed to the sniffer, so both the number of
		// rounds and how much they grew by are pinned down
		seen []int
	}{
		{
			// a sniffer that discovers its needs incrementally (HTTP/2: preface,
			// then frame header, then payload) must be fed again until it decides
			name:   "retries until the sniffer reaches a verdict",
			chunks: threeSegments,
			reply: func(data []byte) (string, error) {
				for _, want := range []int{20, 30} {
					if len(data) < want {
						return "", needAtLeast(want)
					}
				}
				return "example.com", nil
			},
			host: "example.com",
			seen: []int{10, 20, 30},
		},
		{
			// asking for one more byte still advances a whole segment at a time,
			// because every retry is handed everything that arrived
			name:   "hands over all buffered data, not just the extra byte",
			chunks: threeSegments,
			reply: func(data []byte) (string, error) {
				if len(data) < 30 {
					return "", needAtLeast(len(data) + 1)
				}
				return "example.com", nil
			},
			host: "example.com",
			seen: []int{10, 20, 30},
		},
		{
			// a request that does not grow can never be satisfied
			name:   "stops when the request cannot grow",
			chunks: threeSegments,
			reply: func(data []byte) (string, error) {
				return "", needAtLeast(len(data))
			},
			wantErr: true,
			seen:    []int{10},
		},
		{
			// Peek cannot return more than the buffer holds
			name:   "stops when the request exceeds the peek limit",
			chunks: threeSegments,
			reply: func(data []byte) (string, error) {
				return "", needAtLeast(1 << 20)
			},
			wantErr: true,
			seen:    []int{10},
		},
		{
			name:   "gives up when the data never completes",
			chunks: [][]byte{segment},
			reply: func(data []byte) (string, error) {
				return "", needAtLeast(len(data) + 1)
			},
			wantErr: true,
			seen:    []int{10},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &stubSniffer{reply: test.reply}
			sd := &Dispatcher{enable: true, sniffers: map[sniffer.Sniffer]SnifferConfig{s: {}}}
			raw := &chunkedConn{t: t, chunks: test.chunks}
			// a leaked deadline must not fire once the test is over
			t.Cleanup(raw.stopTimer)
			conn := N.NewBufferedConn(raw)

			host, err := sd.sniffDomain(conn, &C.Metadata{NetWork: C.TCP, DstPort: 80})

			if test.wantErr {
				assert.Error(t, err)
				assert.Empty(t, host)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.host, host)
			}
			assert.Equal(t, test.seen, s.seen)
			// sniffing must not leave a deadline behind for the relay that follows
			assert.True(t, raw.deadline.IsZero(), "read deadline was not cleared")
		})
	}
}
