package httpmask

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mhttp "github.com/metacubex/http"
)

type roundTripFunc func(*mhttp.Request) (*mhttp.Response, error)

func (f roundTripFunc) RoundTrip(req *mhttp.Request) (*mhttp.Response, error) {
	return f(req)
}

func TestEarlyHandshakeConnPreservesHalfClose(t *testing.T) {
	client, peer := newHalfPipe()
	defer client.Close()
	defer peer.Close()

	wrapped := wrapEarlyHandshakeConn(client, "user")
	if err := wrapped.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	var one [1]byte
	if n, err := peer.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer read = (%d, %v), want EOF", n, err)
	}

	response := make([]byte, len("response"))
	go func() { _, _ = peer.Write([]byte("response")) }()
	if _, err := io.ReadFull(wrapped, response); err != nil {
		t.Fatalf("read after close write: %v", err)
	}
}

func TestTunnelHalfClosePreservesResponse(t *testing.T) {
	tests := []struct {
		name string
		dial func(context.Context, string, TunnelDialOptions) (net.Conn, error)
	}{
		{name: "stream", dial: dialStream},
		{name: "poll", dial: dialPoll},
		{name: "auto", dial: DialTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewTunnelServer(TunnelServerOptions{
				Mode:            "auto",
				PullReadTimeout: 50 * time.Millisecond,
				SessionTTL:      2 * time.Second,
			})
			addr, stop, tunnels := startTestTunnelServer(t, server)
			defer stop()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := tt.dial(ctx, addr, TunnelDialOptions{
				Mode:        tt.name,
				DialContext: (&net.Dialer{}).DialContext,
				Multiplex:   "auto",
			})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			tunnel := <-tunnels
			defer tunnel.Close()

			request := []byte("request body")
			response := []byte("response after request EOF")
			serverDone := make(chan error, 1)
			go func() {
				got, err := io.ReadAll(tunnel)
				if err == nil && !bytes.Equal(got, request) {
					err = io.ErrUnexpectedEOF
				}
				if err == nil {
					_, err = tunnel.Write(response)
				}
				if err == nil {
					err = tunnel.(interface{ CloseWrite() error }).CloseWrite()
				}
				serverDone <- err
			}()

			if _, err := conn.Write(request); err != nil {
				t.Fatalf("write request: %v", err)
			}
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatalf("close write: %v", err)
			}
			got, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if !bytes.Equal(got, response) {
				t.Fatalf("response mismatch: got %q want %q", got, response)
			}
			if err := <-serverDone; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestQueuedConnReadEOFDrainsBufferedPayload(t *testing.T) {
	conn := &queuedConn{
		rxc:     make(chan []byte, 1),
		closed:  make(chan struct{}),
		readEOF: make(chan struct{}),
	}
	conn.rxc <- []byte("final payload")
	conn.markReadEOF()

	got := make([]byte, len("final payload"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read final payload: %v", err)
	}
	if string(got) != "final payload" {
		t.Fatalf("final payload = %q", got)
	}
	var one [1]byte
	if n, err := conn.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after final payload = (%d, %v), want EOF", n, err)
	}
}

func TestSendSessionControlRetriesTransportEOF(t *testing.T) {
	var calls atomic.Int32
	client := &mhttp.Client{Transport: roundTripFunc(func(req *mhttp.Request) (*mhttp.Response, error) {
		if req.Method != mhttp.MethodPost || req.URL.Query().Get("fin") != "1" {
			t.Fatalf("unexpected control request: %s %s", req.Method, req.URL)
		}
		if calls.Add(1) == 1 {
			return nil, io.EOF
		}
		return &mhttp.Response{
			StatusCode: mhttp.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("OK")),
			Header:     make(mhttp.Header),
		}, nil
	})}

	if err := sendSessionControl(
		client,
		"http://example/api/v1/upload?token=session&fin=1",
		"example",
		TunnelModeStream,
		newTunnelAuth("", 0),
	); err != nil {
		t.Fatalf("send session control: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("control calls = %d, want 2", calls.Load())
	}
}

func TestTunnelServerSessionControlIsIdempotent(t *testing.T) {
	for _, mode := range []TunnelMode{TunnelModeStream, TunnelModePoll} {
		for _, control := range []string{"fin", "close"} {
			t.Run(string(mode)+"/"+control, func(t *testing.T) {
				server := NewTunnelServer(TunnelServerOptions{
					Mode:                "auto",
					PassThroughOnReject: true,
				})
				clientConn, serverConn := net.Pipe()
				defer clientConn.Close()

				done := make(chan struct {
					result HandleResult
					err    error
				}, 1)
				go func() {
					result, _, err := server.HandleConn(serverConn)
					done <- struct {
						result HandleResult
						err    error
					}{result: result, err: err}
				}()

				request := fmt.Sprintf(
					"POST /api/v1/upload?token=already-closed&%s=1 HTTP/1.1\r\n"+
						"Host: example.com\r\n"+
						"X-Sudoku-Tunnel: %s\r\n"+
						"Content-Length: 0\r\n\r\n",
					control, mode,
				)
				if _, err := io.WriteString(clientConn, request); err != nil {
					t.Fatalf("write control request: %v", err)
				}
				response, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodPost})
				if err != nil {
					t.Fatalf("read control response: %v", err)
				}
				_ = response.Body.Close()
				result := <-done
				if result.err != nil {
					t.Fatalf("handle control request: %v", result.err)
				}
				if result.result != HandleDone {
					t.Fatalf("control result = %v, want HandleDone", result.result)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("control status = %d, want 200", response.StatusCode)
				}
			})
		}
	}
}

func startTestTunnelServer(t testing.TB, server *TunnelServer) (string, func(), <-chan net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tunnels := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				result, tunnel, err := server.HandleConn(raw)
				if err != nil {
					_ = raw.Close()
					return
				}
				if result == HandleStartTunnel {
					tunnels <- tunnel
				}
			}()
		}
	}()

	stop := func() {
		_ = listener.Close()
		<-done
	}
	return listener.Addr().String(), stop, tunnels
}

func TestTunnelServerDownlinkHalfCloseKeepsUplink(t *testing.T) {
	tests := []struct {
		name     string
		pull     func(*TunnelServer, net.Conn, string) (HandleResult, net.Conn, error)
		push     func(*TunnelServer, net.Conn, string, io.Reader) (HandleResult, net.Conn, error)
		pushBody string
	}{
		{
			name:     "stream",
			pull:     (*TunnelServer).streamPull,
			push:     (*TunnelServer).streamPush,
			pushBody: "tail",
		},
		{
			name:     "poll",
			pull:     (*TunnelServer).pollPull,
			push:     (*TunnelServer).pollPush,
			pushBody: base64.StdEncoding.EncodeToString([]byte("tail")) + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const token = "half-closed-session"

			appConn, sessionConn := newHalfPipe()
			server := NewTunnelServer(TunnelServerOptions{PullReadTimeout: 20 * time.Millisecond})
			server.sessions[token] = &tunnelSession{conn: sessionConn}
			t.Cleanup(func() {
				_ = appConn.Close()
				server.sessionClose(token)
			})

			appDone := make(chan error, 1)
			go func() {
				if _, err := appConn.Write([]byte("response")); err != nil {
					appDone <- err
					return
				}
				if err := appConn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					appDone <- err
					return
				}
				tail, err := io.ReadAll(appConn)
				if err == nil && string(tail) != "tail" {
					err = fmt.Errorf("tail = %q", tail)
				}
				appDone <- err
			}()

			clientConn, serverConn := net.Pipe()
			done := make(chan error, 1)
			go func() {
				_, _, err := tt.pull(server, serverConn, token)
				done <- err
			}()

			resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			_ = clientConn.Close()
			if err := <-done; err != nil {
				t.Fatalf("poll pull: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusOK)
			}
			if got := resp.Trailer.Get(tunnelStreamEOFHeader); got != "1" {
				t.Fatalf("EOF trailer = %q, want 1", got)
			}
			if !server.sessionHas(token) {
				t.Fatal("session removed after downlink EOF")
			}

			clientConn, serverConn = net.Pipe()
			done = make(chan error, 1)
			go func() {
				_, _, err := tt.push(server, serverConn, token, strings.NewReader(tt.pushBody))
				done <- err
			}()
			resp, err = http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatalf("read push response: %v", err)
			}
			_ = resp.Body.Close()
			_ = clientConn.Close()
			if err := <-done; err != nil {
				t.Fatalf("push: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("push status: got %d want %d", resp.StatusCode, http.StatusOK)
			}

			server.sessionCloseWrite(token)
			if err := <-appDone; err != nil {
				t.Fatalf("application: %v", err)
			}
			if server.sessionHas(token) {
				t.Fatal("session retained after both directions closed")
			}
		})
	}
}
