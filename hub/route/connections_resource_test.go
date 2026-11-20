package route

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func resourceConnectionRequest(interval string) *http.Request {
	r := httptest.NewRequest("GET", "http://localhost/connections?interval="+interval, nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return r
}
func TestResourceConnectionsRejectInvalidBeforeUpgrade(t *testing.T) {
	for _, value := range []string{"abc", "0", "-1", "9223372036854775807", "9223372036855", "999999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			w := httptest.NewRecorder()
			getConnections(w, resourceConnectionRequest(value))
			if w.Code != 400 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	r := httptest.NewRequest("GET", "http://localhost/connections?interval=0", nil)
	w := httptest.NewRecorder()
	getConnections(w, r)
	if w.Code != 200 {
		t.Fatal("plain HTTP behavior changed", w.Code)
	}
}
func resourceWaitHandler(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection handler retained after disconnect")
	}
}
func resourceWebSocket(t *testing.T, url string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(url, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(conn, "GET /connections?interval=3600000 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, " 101 ") {
		t.Fatalf("upgrade=%q err=%v", line, err)
	}
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	messages, err := wsutil.ReadServerMessage(reader, nil)
	if err != nil || len(messages) != 1 || messages[0].OpCode != ws.OpText {
		t.Fatalf("initial snapshot: %v %v", messages, err)
	}
	return conn, reader
}
func TestResourceConnectionsLifecycle(t *testing.T) {
	for _, mode := range []string{"tcp-close", "websocket-close", "websocket-half-close", "ping", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(done); getConnections(w, r.WithContext(ctx)) }))
			defer srv.Close()
			conn, reader := resourceWebSocket(t, srv.URL)
			switch mode {
			case "ping":
				if err := wsutil.WriteClientMessage(conn, ws.OpPing, []byte("alive")); err != nil {
					t.Fatal(err)
				}
				messages, err := wsutil.ReadServerMessage(reader, nil)
				if err != nil || len(messages) != 1 || messages[0].OpCode != ws.OpPong || string(messages[0].Payload) != "alive" {
					t.Fatalf("pong: %v %v", messages, err)
				}
				_ = conn.Close()
			case "websocket-close", "websocket-half-close":
				if err := wsutil.WriteClientMessage(conn, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, "bye")); err != nil {
					t.Fatal(err)
				}
				if mode == "websocket-half-close" {
					if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
						t.Fatal(err)
					}
				}
				messages, err := wsutil.ReadServerMessage(reader, nil)
				if err != nil || len(messages) != 1 || messages[0].OpCode != ws.OpClose {
					t.Fatalf("close response: %v %v", messages, err)
				}
			case "cancel":
				cancel()
			default:
				_ = conn.Close()
			}
			resourceWaitHandler(t, done)
		})
	}
}
func TestResourceConnectionsBufferedControlAndReadError(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			controls := make(chan wsutil.Message, 4)
			stop := make(chan struct{})
			done := make(chan struct{})
			// A control frame may already be buffered by the HTTP hijacker.
			frame := ws.NewPingFrame([]byte("buffered"))
			if bad {
				frame.Header.Masked = false
			} else {
				frame = ws.MaskFrameInPlace(frame)
			}
			var encoded strings.Builder
			if err := ws.WriteFrame(&encoded, frame); err != nil {
				t.Fatal(err)
			}
			go func() {
				defer close(done)
				readConnectionControls(server, io.MultiReader(strings.NewReader(encoded.String()), server), controls, stop)
			}()
			if !bad {
				select {
				case msg := <-controls:
					if msg.OpCode != ws.OpPing || string(msg.Payload) != "buffered" {
						t.Fatal("buffered frame lost")
					}
				case <-time.After(time.Second):
					t.Fatal("buffered frame not consumed")
				}
			}
			if bad {
				// An unmasked frame must terminate while the peer remains open.
				resourceWaitHandler(t, done)
				if _, ok := <-controls; ok {
					t.Fatal("unmasked frame accepted")
				}
			} else {
				_ = client.Close()
				resourceWaitHandler(t, done)
			}
			close(stop)
		})
	}
}
func TestResourceConnectionsControlBackpressure(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	controls := make(chan wsutil.Message, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { defer close(done); readConnectionControls(server, server, controls, stop) }()
	for i := 0; i < 2; i++ {
		if err := wsutil.WriteClientMessage(client, ws.OpPing, nil); err != nil && i == 0 {
			t.Fatal(err)
		}
	}
	resourceWaitHandler(t, done)
	close(stop)
}

type resourceHijacker struct {
	*httptest.ResponseRecorder
	conn   net.Conn
	source io.Reader
}

func (h *resourceHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.source), bufio.NewWriter(h.conn)), nil
}
func TestResourceConnectionsBlockedWriteExit(t *testing.T) {
	for _, mode := range []string{"cancel", "peer-eof", "websocket-close", "fragmented-close"} {
		t.Run(mode, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			writer := &resourceHijacker{httptest.NewRecorder(), server, server}
			go func() {
				defer close(done)
				getConnections(writer, resourceConnectionRequest("3600000").WithContext(ctx))
			}()
			reader := bufio.NewReader(client)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				if line == "\r\n" {
					break
				}
			}
			// net.Pipe has no write buffer: the initial snapshot blocks until read.
			switch mode {
			case "cancel":
				cancel()
			case "peer-eof":
				_ = client.Close()
			default:
				if mode == "fragmented-close" {
					first := ws.NewTextFrame([]byte("partial"))
					first.Header.Fin = false
					if err := ws.WriteFrame(client, ws.MaskFrameInPlace(first)); err != nil {
						t.Fatal(err)
					}
				}
				if err := wsutil.WriteClientMessage(client, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, "bye")); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(connectionCloseGrace + 3*time.Second):
				t.Fatal("blocked writer retained after close/cancel/EOF")
			}
		})
	}
}
func TestResourceConnectionsUpgradeFlushFailure(t *testing.T) {
	server, client := net.Pipe()
	_ = client.Close()
	writer := &resourceHijacker{httptest.NewRecorder(), server, server}
	getConnections(writer, resourceConnectionRequest("1000"))
	// net.Pipe reports closed on a read deadline only after our end is closed.
	if err := server.SetReadDeadline(time.Now()); err != io.ErrClosedPipe {
		t.Fatalf("hijacked socket retained: %v", err)
	}
	_ = server.Close()
}

func TestResourceConnectionsPrefetchedClose(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	var prefetched strings.Builder
	if err := ws.WriteFrame(&prefetched, ws.MaskFrameInPlace(ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "bye")))); err != nil {
		t.Fatal(err)
	}
	writer := &resourceHijacker{httptest.NewRecorder(), server, io.MultiReader(strings.NewReader(prefetched.String()), server)}
	done := make(chan struct{})
	go func() { defer close(done); getConnections(writer, resourceConnectionRequest("3600000")) }()
	reader := bufio.NewReader(client)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	for _, op := range []ws.OpCode{ws.OpText, ws.OpClose} {
		messages, err := wsutil.ReadServerMessage(reader, nil)
		if err != nil || len(messages) != 1 || messages[0].OpCode != op {
			t.Fatalf("prefetched close opcode=%v messages=%v error=%v", op, messages, err)
		}
	}
	resourceWaitHandler(t, done)
}
