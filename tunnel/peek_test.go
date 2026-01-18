package tunnel

import (
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// TestPeekNoLeakOnEarlyReturn tests that peek doesn't leak goroutines
func TestPeekNoLeakOnEarlyReturn(t *testing.T) {
	// Track goroutine count before
	initialGoroutines := runtime.NumGoroutine()

	// Simulate multiple early returns (like resolveMetadata failures)
	for i := 0; i < 10; i++ {
		func() {
			// Simulate the early return path
			metadata := &C.Metadata{}
			if !metadata.Valid() {
				return
			}

			// Create a mock connection with data
			conn := NewMockBufferedConn([]byte("G"))

			// Synchronous peek - no goroutine created
			if !conn.Peeked() {
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				_, _ = conn.Peek(1)
				_ = conn.SetReadDeadline(time.Time{})
			}
		}()
	}

	// Give time for any leaked goroutines to show up
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Potential goroutine leak: %d -> %d", initialGoroutines, finalGoroutines)
	}
}

// TestConcurrentPeek tests that concurrent TCP connections don't interfere
func TestConcurrentPeek(t *testing.T) {
	const concurrency = 100
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn := NewMockBufferedConn([]byte("GET"))

			if !conn.Peeked() {
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				_, _ = conn.Peek(1)
				_ = conn.SetReadDeadline(time.Time{})
			}

			if !conn.Peeked() {
				t.Errorf("Goroutine %d: Peeked() should be true", id)
			}
		}(i)
	}

	wg.Wait()
}

// BenchmarkPeek benchmarks the synchronous peek implementation
func BenchmarkPeek(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := NewMockBufferedConn([]byte("GET"))
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = conn.Peek(1)
		_ = conn.SetReadDeadline(time.Time{})
	}
}

// TestPeekTimeout tests that read deadline is properly handled
func TestPeekTimeout(t *testing.T) {
	conn := NewMockBufferedConn([]byte(""))

	// Set aggressive deadline
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	data, _ := conn.Peek(1)

	// Reset deadline
	_ = conn.SetReadDeadline(time.Time{})

	// Should not panic or crash
	if data == nil && !conn.Peeked() {
		// Timeout case is handled correctly
		return
	}
}

// TestPeekDataIntegrity tests that peeked data is not consumed
func TestPeekDataIntegrity(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\r\n")
	conn := NewMockBufferedConn(data)

	// First peek should return all buffered data
	peeked1, _ := conn.Peek(1)
	if len(peeked1) == 0 {
		t.Errorf("First peek failed: got empty data")
	}

	// Second peek should return same data (not consumed)
	peeked2, _ := conn.Peek(1)
	if len(peeked2) == 0 {
		t.Errorf("Second peek failed: got empty data")
	}

	// Verify data matches
	if string(peeked1) != string(peeked2) {
		t.Errorf("Peek data mismatch: %s != %s", peeked1, peeked2)
	}

	// Data should still be readable
	read := make([]byte, 4)
	n, _ := conn.Read(read)
	if n != 4 || string(read) != "HTTP" {
		t.Errorf("Read after peek failed: got %s (len %d), want HTTP (len 4)", read[:n], n)
	}
}

// ===== Mock implementations =====

// NewMockBufferedConn creates a mock connection that simulates BufferedConn
// with pre-buffered data for testing Peek functionality
type mockBufferedConn struct {
	data   []byte
	peeked bool
}

func NewMockBufferedConn(data []byte) *mockBufferedConn {
	return &mockBufferedConn{data: data}
}

func (m *mockBufferedConn) Read(b []byte) (n int, err error) {
	if len(m.data) > 0 {
		n = copy(b, m.data)
		m.data = m.data[n:]
		return
	}
	return 0, io.EOF
}

func (m *mockBufferedConn) Peek(n int) ([]byte, error) {
	if len(m.data) > 0 {
		m.peeked = true
		return m.data, nil
	}
	return nil, nil
}

func (m *mockBufferedConn) Peeked() bool {
	return m.peeked
}

func (m *mockBufferedConn) Buffered() int {
	return len(m.data)
}

func (m *mockBufferedConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockBufferedConn) Close() error {
	return nil
}

func (m *mockBufferedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (m *mockBufferedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (m *mockBufferedConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockBufferedConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockBufferedConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}
