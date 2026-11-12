package ratelimit

import (
	"net"
	"testing"
	"time"
)

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"", 0},
		{"0", 0},
		{"500k", 500_000},
		{"500K", 500_000},
		{"500kbps", 500_000},
		{"500Kbps", 500_000},
		{"1m", 1_000_000},
		{"1M", 1_000_000},
		{"1Mbps", 1_000_000},
		{"2g", 2_000_000_000},
		{"1", 1_000_000}, // bare number = Mbps
		{"  500k  ", 500_000},
		{"bogus", 0},
	}
	for _, tc := range cases {
		got := ParseBandwidth(tc.in)
		if got != tc.want {
			t.Errorf("ParseBandwidth(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestNewRateLimitedConn_ZeroRate(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	conn := NewRateLimitedConn(client, 0)
	if conn != client {
		t.Error("zero rate should return original connection")
	}
}

func TestNewRateLimitedConn_WithRate(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// 1 Mbps = 1,000,000 bits per second
	conn := NewRateLimitedConn(client, 1_000_000)
	if conn == client {
		t.Error("non-zero rate should return wrapped connection")
	}

	rlc, ok := conn.(*RateLimitedConn)
	if !ok {
		t.Fatal("should return *RateLimitedConn")
	}
	if rlc.burst == 0 {
		t.Error("burst should be non-zero")
	}
}

func TestBitRateLimiter_Reservation(t *testing.T) {
	limiter := &bitRateLimiter{rateBps: 800}
	now := time.Unix(0, 0)
	if delay := limiter.reserveN(now, 1); delay != 0 {
		t.Fatalf("initial reservation delay = %s, want 0", delay)
	}
	if delay := limiter.reserveN(now, 1); delay != 10*time.Millisecond {
		t.Fatalf("second reservation delay = %s, want 10ms", delay)
	}
}

func TestRateLimitedConn_ReadWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// 8 Mbps = 1 MB/s → 1 byte every 1µs theoretically; use high enough for test
	limited := NewRateLimitedConn(client, 8_000_000)

	go func() {
		buf := make([]byte, 100)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("pong"))
	}()

	n, err := limited.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 4 {
		t.Fatalf("wrote %d, want 4", n)
	}

	buf := make([]byte, 4)
	n, err = limited.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("read %q, want pong", buf[:n])
	}
}

func TestRateLimitedConn_BurstLimits(t *testing.T) {
	// 800 bps → burst = 800/8/(1000/10) = 1
	conn := NewRateLimitedConn(&net.TCPConn{}, 800)
	rlc := conn.(*RateLimitedConn)
	if rlc.burst != 1 {
		t.Fatalf("burst = %d, want 1", rlc.burst)
	}
}

func TestRateLimitedConn_HighRateBurstCap(t *testing.T) {
	// Very high rate should cap burst at 64KB
	conn := NewRateLimitedConn(&net.TCPConn{}, 100_000_000_000)
	rlc := conn.(*RateLimitedConn)
	if rlc.burst != maxRateLimitBurstBytes {
		t.Fatalf("burst = %d, want %d", rlc.burst, maxRateLimitBurstBytes)
	}
}

func TestLimiter_SharedAcrossConns(t *testing.T) {
	lim := NewLimiter(800) // 800 bps = 100 B/s
	if lim == nil {
		t.Fatal("expected non-nil limiter")
	}
	if lim.Rate() != 800 {
		t.Fatalf("rate = %d, want 800", lim.Rate())
	}

	// Both wraps must share the same underlying limiters.
	s1, c1 := net.Pipe()
	defer s1.Close()
	defer c1.Close()
	s2, c2 := net.Pipe()
	defer s2.Close()
	defer c2.Close()

	w1 := lim.WrapConn(c1).(*RateLimitedConn)
	w2 := lim.WrapConn(c2).(*RateLimitedConn)
	if w1.readLimiter != w2.readLimiter || w1.writeLimiter != w2.writeLimiter {
		t.Fatal("wrapped conns must share the same limiters")
	}
}

func TestNewLimiter_Zero(t *testing.T) {
	if NewLimiter(0) != nil {
		t.Fatal("zero rate should return nil limiter")
	}
}

func TestRateLimitedConn_Throughput(t *testing.T) {
	// 16_000 bps = 2_000 B/s. 4_000 bytes should take ~2s.
	const rateBps = 16_000
	const payload = 4_000

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	limited := NewRateLimitedConn(client, rateBps)

	go func() {
		_, _ = server.Write(make([]byte, payload))
		_ = server.Close()
	}()

	start := time.Now()
	buf := make([]byte, 512)
	var total int
	for {
		n, err := limited.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)
	if total != payload {
		t.Fatalf("read %d, want %d", total, payload)
	}
	if elapsed < time.Second {
		t.Fatalf("read too fast: %s for %d bytes at %d bps", elapsed, payload, rateBps)
	}
}

func TestLimitedCConn_NotReplaceable(t *testing.T) {
	c := &limitedCConn{}
	if c.ReaderReplaceable() {
		t.Fatal("ReaderReplaceable must be false")
	}
	if c.WriterReplaceable() {
		t.Fatal("WriterReplaceable must be false")
	}
}
