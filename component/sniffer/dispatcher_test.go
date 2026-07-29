package sniffer

// Tests for the Dispatcher's data-feeding loop: how much data a sniffer is
// handed, when it is asked again, and when the dispatcher gives up. Protocol
// parsing itself (a complete buffer in, a domain out) belongs in sniff_test.go.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"

	"github.com/stretchr/testify/assert"
)

// chunkedConn hands out one chunk per Read, so a sniffer only ever sees the
// bytes that have "arrived". It models a request spanning several TCP segments,
// and reports readErr, or EOF by default, once they run out.
//
// Read deadlines are armed for real: the deadline is a watchdog that must never
// fire, because sniffing should reach a verdict from the data it is given rather
// than sit and wait. A read that would block without any deadline set fails the
// test too, since that is a conn stuck forever.
type chunkedConn struct {
	net.Conn
	t         *testing.T
	chunks    [][]byte
	readErr   error
	closed    bool
	deadline  time.Time
	deadlines []time.Time
	timer     *time.Timer
}

func (c *chunkedConn) Read(b []byte) (int, error) {
	if len(c.chunks) > 0 {
		chunk := c.chunks[0]
		c.chunks = c.chunks[1:]
		return copy(b, chunk), nil
	}
	if c.readErr != nil {
		return 0, c.readErr
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
		c.deadlines = append(c.deadlines, deadline)
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

func (c *chunkedConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *chunkedConn) Close() error {
	c.closed = true
	return nil
}
func (*chunkedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*chunkedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*chunkedConn) SetDeadline(time.Time) error      { return nil }
func (*chunkedConn) SetWriteDeadline(time.Time) error { return nil }

// stubSniffer records the size of every buffer it is handed and replies with a
// scripted answer, so the feeding loop can be tested without any real protocol.
type stubSniffer struct {
	network C.NetWork
	seen    []int
	reply   func(data []byte) (string, error)
}

type domainMatcherFunc func(domain string) bool

func (f domainMatcherFunc) MatchDomain(domain string) bool { return f(domain) }

var _ sniffer.Sniffer = (*stubSniffer)(nil)

func (s *stubSniffer) SupportNetwork() C.NetWork { return s.network }
func (*stubSniffer) Protocol() string            { return "stub" }
func (*stubSniffer) SupportPort(uint16) bool     { return true }

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
	largeSize := 5000

	tests := []struct {
		name    string
		chunks  [][]byte
		reply   func(data []byte) (string, error)
		host    string
		wantErr bool
		// size of each buffer handed to the sniffer, so both the number of
		// rounds and how much they grew by are pinned down
		seen       []int
		bufferSize int
		buffered   int
		chunksLeft int
		errorIs    error
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
			// requests beyond bufio.Reader's default capacity should expand the
			// buffer before the dispatcher retries Peek
			name:   "grows the peek buffer on demand",
			chunks: [][]byte{segment, bytes.Repeat([]byte("x"), largeSize-len(segment))},
			reply: func(data []byte) (string, error) {
				if len(data) < largeSize {
					return "", needAtLeast(largeSize)
				}
				return "example.com", nil
			},
			host:       "example.com",
			seen:       []int{10, largeSize},
			bufferSize: 8192,
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
			// An oversized request must be rejected before the reader grows or
			// consumes more data while trying to fill its buffer.
			name:   "stops when the request exceeds the peek limit",
			chunks: threeSegments,
			reply: func(data []byte) (string, error) {
				return "", needAtLeast(1 << 20)
			},
			wantErr:    true,
			errorIs:    bufio.ErrBufferFull,
			seen:       []int{10},
			bufferSize: 4096,
			buffered:   10,
			chunksLeft: 2,
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
			sd := &Dispatcher{enable: true, sniffers: []configuredSniffer{{Sniffer: s}}}
			raw := &chunkedConn{t: t, chunks: test.chunks}
			// a leaked deadline must not fire once the test is over
			t.Cleanup(raw.stopTimer)
			conn := N.NewBufferedConn(raw)

			host, _, err := sd.sniffDomain(conn, &C.Metadata{NetWork: C.TCP, DstPort: 80})

			if test.wantErr {
				assert.Error(t, err)
				assert.Empty(t, host)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.host, host)
			}
			if test.errorIs != nil {
				assert.ErrorIs(t, err, test.errorIs)
			}
			assert.Equal(t, test.seen, s.seen)
			if test.bufferSize != 0 {
				assert.Equal(t, test.bufferSize, conn.Reader().Size())
			}
			if test.buffered != 0 {
				assert.Equal(t, test.buffered, conn.Buffered())
			}
			if test.chunksLeft != 0 {
				assert.Len(t, raw.chunks, test.chunksLeft)
			}
			// sniffing must not leave a deadline behind for the relay that follows
			assert.True(t, raw.deadline.IsZero(), "read deadline was not cleared")
			assert.GreaterOrEqual(t, len(raw.deadlines), 2, "initial and shared deadlines must both be set")
			for _, deadline := range raw.deadlines[2:] {
				assert.Equal(t, raw.deadlines[1], deadline, "all retries must reuse the shared deadline")
			}
		})
	}
}

func TestDispatcherMultipleSniffers(t *testing.T) {
	segment := []byte("0123456789")

	t.Run("uses the successful sniffer config before reading more", func(t *testing.T) {
		waiting := &stubSniffer{reply: func(data []byte) (string, error) {
			return "", needAtLeast(len(data) + 1)
		}}
		successful := &stubSniffer{reply: func([]byte) (string, error) {
			return "example.com", nil
		}}
		sd, err := NewDispatcher(&Config{Enable: true, ParsePureIp: true})
		assert.NoError(t, err)
		sd.sniffers = []configuredSniffer{
			{Sniffer: waiting, config: SnifferConfig{OverrideDest: false}},
			{Sniffer: successful, config: SnifferConfig{OverrideDest: true}},
		}
		raw := &chunkedConn{t: t, chunks: [][]byte{segment, segment}}
		t.Cleanup(raw.stopTimer)
		metadata := &C.Metadata{
			NetWork: C.TCP,
			DstIP:   netip.MustParseAddr("192.0.2.1"),
			DstPort: 80,
		}

		sniffed := sd.TCPSniff(N.NewBufferedConn(raw), metadata)

		assert.True(t, sniffed)
		assert.Equal(t, "example.com", metadata.SniffHost)
		assert.Equal(t, "example.com", metadata.Host)
		assert.False(t, metadata.DstIP.IsValid())
		assert.Equal(t, []int{len(segment)}, waiting.seen)
		assert.Equal(t, []int{len(segment)}, successful.seen)
		assert.Len(t, raw.chunks, 1)
		assert.True(t, raw.deadline.IsZero(), "read deadline was not cleared")
		assert.Len(t, raw.deadlines, 2, "one initial and one shared deadline should be sufficient")
	})

	t.Run("reads the smallest candidate request next", func(t *testing.T) {
		slow := &stubSniffer{reply: func(data []byte) (string, error) {
			if len(data) < 30 {
				return "", needAtLeast(30)
			}
			return "slow.example.com", nil
		}}
		fast := &stubSniffer{reply: func(data []byte) (string, error) {
			if len(data) < 20 {
				return "", needAtLeast(20)
			}
			return "fast.example.com", nil
		}}
		sd := &Dispatcher{sniffers: []configuredSniffer{
			{Sniffer: slow},
			{Sniffer: fast},
		}}
		raw := &chunkedConn{t: t, chunks: [][]byte{segment, segment, segment}}
		t.Cleanup(raw.stopTimer)

		host, _, err := sd.sniffDomain(N.NewBufferedConn(raw), &C.Metadata{NetWork: C.TCP, DstPort: 80})

		assert.NoError(t, err)
		assert.Equal(t, "fast.example.com", host)
		assert.Equal(t, []int{10}, slow.seen)
		assert.Equal(t, []int{10, 20}, fast.seen)
		assert.Len(t, raw.chunks, 1)
	})

	t.Run("continues after an invalid host", func(t *testing.T) {
		invalid := &stubSniffer{reply: func([]byte) (string, error) {
			return "not a domain", nil
		}}
		valid := &stubSniffer{reply: func([]byte) (string, error) {
			return "example.com", nil
		}}
		sd := &Dispatcher{sniffers: []configuredSniffer{
			{Sniffer: invalid},
			{Sniffer: valid},
		}}
		raw := &chunkedConn{t: t, chunks: [][]byte{segment}}
		t.Cleanup(raw.stopTimer)

		host, _, err := sd.sniffDomain(N.NewBufferedConn(raw), &C.Metadata{NetWork: C.TCP, DstPort: 80})

		assert.NoError(t, err)
		assert.Equal(t, "example.com", host)
		assert.Equal(t, []int{len(segment)}, invalid.seen)
		assert.Equal(t, []int{len(segment)}, valid.seen)
	})

	t.Run("keeps the connection open after a follow-up read failure", func(t *testing.T) {
		waiting := &stubSniffer{reply: func(data []byte) (string, error) {
			return "", needAtLeast(len(data) + 1)
		}}
		sd, err := NewDispatcher(&Config{})
		assert.NoError(t, err)
		sd.sniffers = []configuredSniffer{{Sniffer: waiting}}
		raw := &chunkedConn{
			t:       t,
			chunks:  [][]byte{segment},
			readErr: &net.OpError{Op: "read", Net: "tcp", Err: io.ErrNoProgress},
		}
		t.Cleanup(raw.stopTimer)
		metadata := &C.Metadata{
			NetWork: C.TCP,
			DstIP:   netip.MustParseAddr("192.0.2.1"),
			DstPort: 80,
		}

		_, _, err = sd.sniffDomain(N.NewBufferedConn(raw), metadata)

		assert.Error(t, err)
		assert.False(t, raw.closed)
		_, cached := sd.skipList.Get(metadata.AddrPort())
		assert.False(t, cached)
	})

	t.Run("keeps the connection open and caches an initial read failure once", func(t *testing.T) {
		waiting := &stubSniffer{reply: func(data []byte) (string, error) {
			return "", needAtLeast(len(data) + 1)
		}}
		sd, err := NewDispatcher(&Config{Enable: true, ParsePureIp: true})
		assert.NoError(t, err)
		sd.sniffers = []configuredSniffer{{Sniffer: waiting}}
		raw := &chunkedConn{
			t:       t,
			readErr: &net.OpError{Op: "read", Net: "tcp", Err: io.ErrNoProgress},
		}
		t.Cleanup(raw.stopTimer)
		metadata := &C.Metadata{
			NetWork: C.TCP,
			DstIP:   netip.MustParseAddr("192.0.2.1"),
			DstPort: 80,
		}

		sniffed := sd.TCPSniff(N.NewBufferedConn(raw), metadata)

		assert.False(t, sniffed)
		assert.False(t, raw.closed)
		assert.Empty(t, waiting.seen)
		failures, cached := sd.skipList.Get(metadata.AddrPort())
		assert.True(t, cached)
		assert.Equal(t, uint8(1), failures)
		assert.True(t, raw.deadline.IsZero(), "read deadline was not cleared")
	})

	t.Run("does not cache a forced initial read failure", func(t *testing.T) {
		waiting := &stubSniffer{reply: func(data []byte) (string, error) {
			return "", needAtLeast(len(data) + 1)
		}}
		sd, err := NewDispatcher(&Config{
			Enable:      true,
			ForceDomain: []C.DomainMatcher{domainMatcherFunc(func(string) bool { return true })},
		})
		assert.NoError(t, err)
		sd.sniffers = []configuredSniffer{{Sniffer: waiting}}
		raw := &chunkedConn{
			t:       t,
			readErr: &net.OpError{Op: "read", Net: "tcp", Err: io.ErrNoProgress},
		}
		t.Cleanup(raw.stopTimer)
		metadata := &C.Metadata{
			NetWork: C.TCP,
			Host:    "forced.example",
			DstIP:   netip.MustParseAddr("192.0.2.1"),
			DstPort: 80,
		}

		sniffed := sd.TCPSniff(N.NewBufferedConn(raw), metadata)

		assert.False(t, sniffed)
		assert.False(t, raw.closed)
		_, cached := sd.skipList.Get(metadata.AddrPort())
		assert.False(t, cached)
	})

	t.Run("accepts all-network sniffer", func(t *testing.T) {
		allNetwork := &stubSniffer{
			network: C.ALLNet,
			reply: func([]byte) (string, error) {
				return "example.com", nil
			},
		}
		sd := &Dispatcher{sniffers: []configuredSniffer{{Sniffer: allNetwork}}}
		raw := &chunkedConn{t: t, chunks: [][]byte{segment}}
		t.Cleanup(raw.stopTimer)

		host, _, err := sd.sniffDomain(N.NewBufferedConn(raw), &C.Metadata{NetWork: C.TCP, DstPort: 80})

		assert.NoError(t, err)
		assert.Equal(t, "example.com", host)
		assert.Equal(t, []int{len(segment)}, allNetwork.seen)
	})

	t.Run("constructs sniffers in protocol order", func(t *testing.T) {
		sd, err := NewDispatcher(&Config{Sniffers: map[sniffer.Type]SnifferConfig{
			sniffer.QUIC: {},
			sniffer.HTTP: {},
			sniffer.TLS:  {},
		}})

		assert.NoError(t, err)
		protocols := make([]string, 0, len(sd.sniffers))
		for _, current := range sd.sniffers {
			protocols = append(protocols, current.Protocol())
		}
		assert.Equal(t, []string{"tls", "http", "quic"}, protocols)
	})
}
