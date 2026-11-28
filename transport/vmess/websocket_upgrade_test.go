package vmess

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/http"
)

type testResponseWriter struct {
	header http.Header
	status int
	body   strings.Builder
}

func (w *testResponseWriter) Header() http.Header         { return w.header }
func (w *testResponseWriter) WriteHeader(statusCode int)  { w.status = statusCode }
func (w *testResponseWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

type testHijackResponseWriter struct {
	testResponseWriter
	conn net.Conn
}

func (w *testHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestStreamUpgradedWebsocketConnValidation(t *testing.T) {
	t.Run("rejects plain GET without committing status or headers", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/ws", nil)
		w := &testResponseWriter{header: make(http.Header)}
		_, err := StreamUpgradedWebsocketConn(w, req)
		if !errors.Is(err, ErrNotWebSocketUpgrade) {
			t.Fatalf("err = %v, want ErrNotWebSocketUpgrade", err)
		}
		if w.status != 0 {
			t.Fatalf("status = %d, want 0", w.status)
		}
		if w.header.Get("Upgrade") != "" {
			t.Fatalf("unexpected Upgrade response header")
		}
	})

	t.Run("rejects non-hijacker writer before writing 101", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/ws", nil)
		req.Header.Set("Upgrade", "WebSocket")
		w := &testResponseWriter{header: make(http.Header)}
		_, err := StreamUpgradedWebsocketConn(w, req)
		if err == nil {
			t.Fatal("expected error for writer without http.Hijacker")
		}
		if w.status != 0 {
			t.Fatalf("status = %d, want 0 (must not commit 101 before Hijacker check)", w.status)
		}
	})

	t.Run("accepts raw HTTPUpgrade without Sec-WebSocket-Key", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		req, _ := http.NewRequest(http.MethodGet, "http://example.com/ws", nil)
		req.Header.Set("Upgrade", "WebSocket")
		w := &testHijackResponseWriter{
			testResponseWriter: testResponseWriter{header: make(http.Header)},
			conn:               c1,
		}
		conn, err := StreamUpgradedWebsocketConn(w, req)
		if err != nil {
			t.Fatalf("raw upgrade failed: %v", err)
		}
		if conn == nil || w.status != http.StatusSwitchingProtocols {
			t.Fatalf("expected 101 and valid conn, got status=%d conn=%v", w.status, conn)
		}
	})
}
