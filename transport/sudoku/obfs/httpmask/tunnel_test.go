package httpmask

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestTunnelHalfClosePreservesResponse(t *testing.T) {
	tests := []struct {
		name string
		dial func(context.Context, string, TunnelDialOptions) (net.Conn, error)
	}{
		{name: "stream", dial: dialStream},
		{name: "poll", dial: dialPoll},
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
				DialContext: (&net.Dialer{}).DialContext,
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

func TestPollPullReapsOnlyFullyClosedSession(t *testing.T) {
	tests := []struct {
		name        string
		closePeer   func(net.Conn) error
		wantStatus  int
		wantAlive   bool
		minDuration time.Duration
	}{
		{
			name: "close-write",
			closePeer: func(conn net.Conn) error {
				return conn.(interface{ CloseWrite() error }).CloseWrite()
			},
			wantStatus:  http.StatusOK,
			wantAlive:   true,
			minDuration: 10 * time.Millisecond,
		},
		{
			name:       "close",
			closePeer:  net.Conn.Close,
			wantStatus: http.StatusGone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const token = "closed-session"

			appConn, sessionConn := newHalfPipe()
			server := NewTunnelServer(TunnelServerOptions{PullReadTimeout: 20 * time.Millisecond})
			server.sessions[token] = &tunnelSession{conn: sessionConn}
			t.Cleanup(func() {
				_ = appConn.Close()
				server.sessionClose(token)
			})

			if err := tt.closePeer(appConn); err != nil {
				t.Fatalf("close peer: %v", err)
			}

			clientConn, serverConn := net.Pipe()
			done := make(chan error, 1)
			started := time.Now()
			go func() {
				_, _, err := server.pollPull(serverConn, token)
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
			if elapsed := time.Since(started); elapsed < tt.minDuration {
				t.Fatalf("poll pull returned after %v, want at least %v", elapsed, tt.minDuration)
			}

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status: got %d want %d", resp.StatusCode, tt.wantStatus)
			}
			if alive := server.sessionHas(token); alive != tt.wantAlive {
				t.Fatalf("session alive: got %v want %v", alive, tt.wantAlive)
			}
		})
	}
}
