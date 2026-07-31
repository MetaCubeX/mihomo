package ratelimit

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
)

const (
	bitsPerByte            = 8
	rateLimitCycle         = 10 * time.Millisecond
	maxRateLimitBurstBytes = 64 * 1024
)

// ParseBandwidth converts human-readable bandwidth to bits per second.
// Accepted: "500k", "1m", "2g", "500kbps", "1Mbps", bare number as Mbps.
// Empty or "0" → 0 (unlimited).
func ParseBandwidth(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0
	}

	// Bare integer → Mbps (same convention as utils.StringToBps).
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return v * 1_000_000
	}

	s = strings.ToLower(strings.ReplaceAll(s, " ", ""))
	s = strings.TrimSuffix(s, "ps") // kbps/mbps → kb/mb
	s = strings.TrimSuffix(s, "b")  // kb/mb → k/m  (or bare bit unit)

	var numStr strings.Builder
	unit := ""
	for i, r := range s {
		if unicode.IsDigit(r) {
			numStr.WriteRune(r)
			continue
		}
		unit = s[i:]
		break
	}
	if numStr.Len() == 0 {
		return 0
	}
	v, err := strconv.ParseUint(numStr.String(), 10, 64)
	if err != nil || v == 0 {
		return 0
	}

	switch unit {
	case "", "b":
		return v
	case "k":
		return v * 1_000
	case "m":
		return v * 1_000_000
	case "g":
		return v * 1_000_000_000
	case "t":
		return v * 1_000_000_000_000
	default:
		return 0
	}
}

func burstFor(rateBps uint64) int {
	burst := rateBps / bitsPerByte / uint64(time.Second/rateLimitCycle)
	if burst == 0 {
		return 1
	}
	if burst > maxRateLimitBurstBytes {
		return maxRateLimitBurstBytes
	}
	return int(burst)
}

// bitRateLimiter is a token-bucket style rate limiter measured in bits per second.
type bitRateLimiter struct {
	mu      sync.Mutex
	rateBps uint64
	next    time.Time
}

func (l *bitRateLimiter) WaitN(ctx context.Context, n int) error {
	delay := l.reserveN(time.Now(), n)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *bitRateLimiter) reserveN(now time.Time, n int) time.Duration {
	interval := time.Duration(uint64(n) * bitsPerByte * uint64(time.Second) / l.rateBps)

	l.mu.Lock()
	ready := l.next
	if ready.Before(now) {
		ready = now
	}
	delay := ready.Sub(now)
	l.next = ready.Add(interval)
	l.mu.Unlock()
	return delay
}

// Limiter is a shared bidirectional bandwidth limiter.
// Connections wrapped by the same Limiter share one rate budget.
type Limiter struct {
	rateBps      uint64
	burst        int
	readLimiter  *bitRateLimiter
	writeLimiter *bitRateLimiter
}

// NewLimiter creates a shared limiter at rateBps bits per second.
// rateBps 0 returns nil (unlimited).
func NewLimiter(rateBps uint64) *Limiter {
	if rateBps == 0 {
		return nil
	}
	return &Limiter{
		rateBps:      rateBps,
		burst:        burstFor(rateBps),
		readLimiter:  &bitRateLimiter{rateBps: rateBps},
		writeLimiter: &bitRateLimiter{rateBps: rateBps},
	}
}

// Rate returns the configured limit in bits per second. Nil-safe.
func (l *Limiter) Rate() uint64 {
	if l == nil {
		return 0
	}
	return l.rateBps
}

// WrapConn wraps a net.Conn with this shared limiter.
func (l *Limiter) WrapConn(conn net.Conn) net.Conn {
	if l == nil {
		return conn
	}
	limitCtx, cancel := context.WithCancel(context.Background())
	return &RateLimitedConn{
		Conn:         conn,
		ctx:          limitCtx,
		cancel:       cancel,
		readLimiter:  l.readLimiter,
		writeLimiter: l.writeLimiter,
		burst:        l.burst,
	}
}

// WrapCConn wraps a C.Conn with this shared limiter.
func (l *Limiter) WrapCConn(conn C.Conn) C.Conn {
	if l == nil {
		return conn
	}
	limitCtx, cancel := context.WithCancel(context.Background())
	return &limitedCConn{
		Conn:         conn,
		ctx:          limitCtx,
		cancel:       cancel,
		readLimiter:  l.readLimiter,
		writeLimiter: l.writeLimiter,
		burst:        l.burst,
	}
}

// RateLimitedConn wraps a net.Conn with per-direction rate limiting.
type RateLimitedConn struct {
	net.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	readLimiter  *bitRateLimiter
	writeLimiter *bitRateLimiter
	burst        int
}

// NewRateLimitedConn wraps conn with a private per-connection limit.
// Prefer Limiter.WrapConn for group-wide shared limits.
func NewRateLimitedConn(conn net.Conn, rateBps uint64) net.Conn {
	return NewLimiter(rateBps).WrapConn(conn)
}

func (c *RateLimitedConn) Read(p []byte) (n int, err error) {
	if len(p) > c.burst {
		p = p[:c.burst]
	}
	n, err = c.Conn.Read(p)
	if n > 0 {
		if limitErr := c.readLimiter.WaitN(c.ctx, n); err == nil {
			err = limitErr
		}
	}
	return
}

func (c *RateLimitedConn) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > c.burst {
			chunkSize = c.burst
		}
		if err = c.writeLimiter.WaitN(c.ctx, chunkSize); err != nil {
			return n, err
		}
		var written int
		written, err = c.Conn.Write(p[:chunkSize])
		n += written
		p = p[written:]
		if err != nil {
			return n, err
		}
		if written != chunkSize {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func (c *RateLimitedConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *RateLimitedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}

// limitedCConn wraps a C.Conn with shared rate limiting.
// It overrides Read/Write AND ReadBuffer/WriteBuffer so bufio.Copy/Relay
// cannot bypass the limiter via ExtendedConn methods promoted by embedding.
//
// Upload rate limiting: WaitN BEFORE write reserves tokens first, then
// the kernel absorbs the write instantly. This limits the rate at which
// data enters the kernel buffer, which controls network throughput.
// (After-write WaitN is useless because TCP kernel buffers absorb instantly.)
//
// Download rate limiting: WaitN AFTER read works because Read blocks when
// kernel buffer is empty, creating backpressure that slows the TCP sender.
type limitedCConn struct {
	C.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	readLimiter  *bitRateLimiter
	writeLimiter *bitRateLimiter
	burst        int
}

// NewLimitedCConn wraps a C.Conn with a private per-connection limit.
func NewLimitedCConn(conn C.Conn, rateBps uint64) C.Conn {
	return NewLimiter(rateBps).WrapCConn(conn)
}

func (c *limitedCConn) Read(p []byte) (n int, err error) {
	if len(p) > c.burst {
		p = p[:c.burst]
	}
	n, err = c.Conn.Read(p)
	if n > 0 {
		if limitErr := c.readLimiter.WaitN(c.ctx, n); err == nil {
			err = limitErr
		}
	}
	return
}

func (c *limitedCConn) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > c.burst {
			chunkSize = c.burst
		}
		// Reserve token BEFORE write so data enters kernel at rate-limited pace.
		if wErr := c.writeLimiter.WaitN(c.ctx, chunkSize); wErr != nil {
			return n, wErr
		}
		var written int
		written, err = c.Conn.Write(p[:chunkSize])
		n += written
		p = p[written:]
		if err != nil {
			return n, err
		}
		if written != chunkSize {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

// ReadBuffer rate-limits ExtendedConn buffer reads used by Relay/bufio.Copy.
func (c *limitedCConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	err := c.Conn.ReadBuffer(buffer)
	n := buffer.Len() - before
	if n > 0 {
		if limitErr := c.readLimiter.WaitN(c.ctx, n); err == nil {
			err = limitErr
		}
	}
	return err
}

// WriteBuffer rate-limits ExtendedConn buffer writes used by Relay/bufio.Copy.
func (c *limitedCConn) WriteBuffer(buffer *buf.Buffer) error {
	// Match ExtendedWriterWrapper: write then release the buffer.
	defer buffer.Release()
	_, err := c.Write(buffer.Bytes())
	return err
}

// ReaderReplaceable reports that Relay must not unwrap past this limiter.
func (c *limitedCConn) ReaderReplaceable() bool { return false }

// WriterReplaceable reports that Relay must not unwrap past this limiter.
func (c *limitedCConn) WriterReplaceable() bool { return false }

func (c *limitedCConn) Upstream() any { return c.Conn }

func (c *limitedCConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *limitedCConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}

// WrapPacketConn wraps a C.PacketConn with shared rate limiting.
func (l *Limiter) WrapPacketConn(pc C.PacketConn) C.PacketConn {
	if l == nil {
		return pc
	}
	limitCtx, cancel := context.WithCancel(context.Background())
	return &limitedPacketConn{
		PacketConn:   pc,
		ctx:          limitCtx,
		cancel:       cancel,
		readLimiter:  l.readLimiter,
		writeLimiter: l.writeLimiter,
	}
}

type limitedPacketConn struct {
	C.PacketConn
	ctx          context.Context
	cancel       context.CancelFunc
	readLimiter  *bitRateLimiter
	writeLimiter *bitRateLimiter
}

func (c *limitedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if n > 0 {
		if limitErr := c.readLimiter.WaitN(c.ctx, n); err == nil {
			err = limitErr
		}
	}
	return
}

// WaitReadFrom overrides the zero-copy UDP read path so rate limiting applies.
func (c *limitedPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	type waitReader interface {
		WaitReadFrom() (data []byte, put func(), addr net.Addr, err error)
	}
	if wr, ok := c.PacketConn.(waitReader); ok {
		data, put, addr, err = wr.WaitReadFrom()
	}
	if len(data) > 0 {
		if limitErr := c.readLimiter.WaitN(c.ctx, len(data)); err == nil {
			err = limitErr
		}
	}
	return
}

func (c *limitedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		if limitErr := c.writeLimiter.WaitN(c.ctx, n); err == nil {
			err = limitErr
		}
	}
	return
}

func (c *limitedPacketConn) Close() error {
	c.cancel()
	return c.PacketConn.Close()
}

func (c *limitedPacketConn) ReaderReplaceable() bool { return false }
func (c *limitedPacketConn) WriterReplaceable() bool { return false }
