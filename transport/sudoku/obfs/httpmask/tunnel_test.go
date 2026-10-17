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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mhttp "github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	"github.com/metacubex/mihomo/common/pool"
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

func TestUploadURLMatchesQueryEncoding(t *testing.T) {
	for _, token := range []string{"T-k_9", "a+b/c=", "sp ace&x=y", "é"} {
		pushURL := "https://h.test/root/api/v1/upload?token=" + url.QueryEscape(token)
		u, err := url.Parse(pushURL)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set(tunnelUploadSequenceQuery, "7")
		u.RawQuery = q.Encode()
		if got := uploadURL(pushURL, 7); got != u.String() {
			t.Fatalf("token %q: uploadURL = %q, want %q", token, got, u.String())
		}
	}
}

func TestQueuedConnRecyclesDrainedPooledPayload(t *testing.T) {
	conn := &queuedConn{
		rxc:    make(chan []byte, 1),
		closed: make(chan struct{}),
	}
	conn.rxc <- pool.Get(streamPullChunkBytes)[:100]

	var buf [60]byte
	if _, err := conn.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	if conn.readPayload == nil {
		t.Fatal("payload released with 40 bytes still unread")
	}
	if n, err := conn.Read(buf[:]); n != 40 || err != nil {
		t.Fatalf("second read = (%d, %v), want 40 bytes", n, err)
	}
	if conn.readPayload != nil {
		t.Fatal("drained payload still held by the conn")
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

func TestTunnelServerPullTakeoverSerializesReaders(t *testing.T) {
	const token = "pull-takeover"

	appConn, sessionConn := newHalfPipe()
	defer appConn.Close()
	defer sessionConn.Close()

	server := NewTunnelServer(TunnelServerOptions{})
	sess := server.sessionAdd(token, sessionConn)

	firstClient, firstServer := net.Pipe()
	defer firstClient.Close()
	defer firstServer.Close()
	first, ok := server.beginSessionPull(token, sess, firstServer)
	if !ok || first == nil {
		t.Fatal("first pull did not acquire a lease")
	}

	secondClient, secondServer := net.Pipe()
	defer secondClient.Close()
	defer secondServer.Close()
	secondDone := make(chan *sessionPullLease, 1)
	go func() {
		lease, _ := server.beginSessionPull(token, sess, secondServer)
		secondDone <- lease
	}()

	select {
	case lease := <-secondDone:
		if lease != nil {
			t.Fatal("second pull acquired the lease before takeover completed")
		}
	case <-time.After(25 * time.Millisecond):
	}

	server.endSessionPull(token, sess, first)
	select {
	case second := <-secondDone:
		if second == nil {
			t.Fatal("second pull did not acquire the lease after takeover")
		}
		server.endSessionPull(token, sess, second)
	case <-time.After(time.Second):
		t.Fatal("second pull remained blocked after first lease ended")
	}
}

func TestPullFrameMatchesChunkedWriter(t *testing.T) {
	payload := bytes.Repeat([]byte("sudoku"), 1000)
	for _, n := range []int{1, 2, 3, 255, 4096, len(payload)} {
		p := payload[:n]

		var want bytes.Buffer
		cw := httputil.NewChunkedWriter(&want)
		_, _ = cw.Write(p)
		if got := streamCodec.appendPullFrame(nil, p); !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("stream frame for %d bytes = %q, want %q", n, got, want.Bytes())
		}

		want.Reset()
		_, _ = cw.Write([]byte(base64.StdEncoding.EncodeToString(p)))
		_, _ = cw.Write([]byte("\n"))
		got := pollCodec.appendPullFrame(make([]byte, 0, pollCodec.pullFrameSize(n)), p)
		if !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("poll frame for %d bytes = %q, want %q", n, got, want.Bytes())
		}
		if len(got) > pollCodec.pullFrameSize(n) {
			t.Fatalf("poll frame for %d bytes is %d, over its size bound %d", n, len(got), pollCodec.pullFrameSize(n))
		}
	}
}

func TestReadUploadGrowsPastPresize(t *testing.T) {
	want := bytes.Repeat([]byte("0123456789abcdef"), 20000) // 320 KB: more than the pooled classes and the presize
	for _, length := range []int64{-1, 0, 100, int64(len(want))} {
		got, err := readUpload(bytes.NewReader(want), length, maxUploadBytes+1)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("declared length %d: read %d bytes, err %v, want %d bytes", length, len(got), err, len(want))
		}
		_ = pool.Put(got)
	}
	got, err := readUpload(bytes.NewReader(want), -1, 1000)
	if err != nil || len(got) != 1000 {
		t.Fatalf("limit: read %d bytes, err %v, want 1000", len(got), err)
	}
	_ = pool.Put(got)
}

func TestDecodeUploadLines(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	got, err := decodeUploadLines([]byte(enc("hello") + "\n\n  \r\n" + enc("w") + "\r\n" + enc("orld")))
	if err != nil || string(got) != "helloworld" {
		t.Fatalf("decode = %q, %v", got, err)
	}
	_ = pool.Put(got)
	if _, err := decodeUploadLines([]byte(enc("ok") + "\n!!!!\n")); err == nil {
		t.Fatal("invalid base64 line was accepted")
	}
}

func TestReadHTTPRequestKeepsReplayAndBody(t *testing.T) {
	raw := "POST /api/v1/upload?token=t HTTP/1.1\r\nHost: x\r\nX-SUDOKU-Tunnel:  poll \r\n" +
		"Content-Length: 5\r\ncontent-length: 9\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\nhello"
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = client.Write([]byte(raw)) }()

	br := bufio.NewReader(server)
	req, _, err := readHTTPRequest(server, br, []byte(raw[:4]))
	if err != nil {
		t.Fatalf("readHTTPRequest: %v", err)
	}
	if req.method != "POST" || req.target != "/api/v1/upload?token=t" || req.tunnel != "poll" || req.contentLength != "5" {
		t.Fatalf("parsed request = %+v", req)
	}
	if !req.isWebSocketUpgrade() {
		t.Fatal("upgrade headers were not recognised")
	}
	if got := req.replayPrefix(); !bytes.HasPrefix([]byte(raw), got) || !bytes.HasPrefix(got, []byte(raw[:len(raw)-5])) {
		t.Fatalf("replay prefix = %q", got)
	}
	body, length, err := req.body()
	if err != nil || length != 5 {
		t.Fatalf("body: length %d, err %v", length, err)
	}
	if got, err := io.ReadAll(body); err != nil || string(got) != "hello" {
		t.Fatalf("body = %q, %v", got, err)
	}
}

func TestTunnelServerReapsIdleSession(t *testing.T) {
	const token = "idle-session"

	appConn, sessionConn := newHalfPipe()
	defer appConn.Close()
	defer sessionConn.Close()

	server := NewTunnelServer(TunnelServerOptions{SessionTTL: 20 * time.Millisecond})
	server.sessionAdd(token, sessionConn)

	// The tunnel read ends once the reaper closes the session pipe.
	readDone := make(chan error, 1)
	go func() {
		_, err := appConn.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("idle session was not reaped")
	}
	if server.sessionHas(token) {
		t.Fatal("reaped session is still registered")
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
		codec    sessionCodec
		pushBody string
	}{
		{
			name:     "stream",
			codec:    streamCodec,
			pushBody: "tail",
		},
		{
			name:     "poll",
			codec:    pollCodec,
			pushBody: base64.StdEncoding.EncodeToString([]byte("tail")) + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const token = "half-closed-session"

			appConn, sessionConn := newHalfPipe()
			server := NewTunnelServer(TunnelServerOptions{PullReadTimeout: 20 * time.Millisecond})
			server.sessionAdd(token, sessionConn)
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
				if err := appConn.CloseWrite(); err != nil {
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
				_, _, err := server.pull(serverConn, token, tt.codec)
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
				_, _, err := server.push(serverConn, token, 1, strings.NewReader(tt.pushBody), -1, tt.codec)
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
