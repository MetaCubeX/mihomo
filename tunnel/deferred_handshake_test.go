package tunnel

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/transport/vmess"
)

type handshakeBudgetProxy struct {
	C.Proxy
	dial func(context.Context) (C.Conn, error)
}

func (p *handshakeBudgetProxy) Name() string { return "handshake-budget" }
func (p *handshakeBudgetProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	return p.dial(ctx)
}

type handshakeBudgetConn struct {
	N.ExtendedConn
	early  bool
	write  func([]byte) (int, error)
	closed chan struct{}
	once   sync.Once
	reject bool
}

// Preserve transport capabilities such as CloseWrite through this test wrapper.
func (c *handshakeBudgetConn) Upstream() any       { return c.ExtendedConn }
func (c *handshakeBudgetConn) NeedHandshake() bool { return c.early }
func (c *handshakeBudgetConn) Chains() C.Chain {
	if c.reject {
		return C.Chain{"REJECT"}
	}
	return C.Chain{"handshake-budget"}
}
func (c *handshakeBudgetConn) ProviderChains() C.Chain       { return nil }
func (c *handshakeBudgetConn) AppendToChains(C.ProxyAdapter) {}
func (c *handshakeBudgetConn) RemoteDestination() string     { return "handshake.invalid" }
func (c *handshakeBudgetConn) Write(b []byte) (int, error) {
	if c.write != nil {
		return c.write(b)
	}
	return c.ExtendedConn.Write(b)
}
func (c *handshakeBudgetConn) Close() error {
	if c.closed != nil {
		c.once.Do(func() { close(c.closed) })
	}
	return c.ExtendedConn.Close()
}
func handshakeBudgetWait(t *testing.T, done <-chan struct{}, limit time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatal("handshake budget lifecycle did not finish")
	}
}

// A real TCP frontend permits a FIN-only request while retaining its read side.
// These tests modify tunnel globals and must not run in parallel.
func startHandshakeBudget(t *testing.T, payload string, dial func(context.Context) (C.Conn, error)) (*net.TCPConn, <-chan struct{}) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	front, err := listener.AcceptTCP()
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	oldStatus, oldProxies := status.Load(), proxies
	status.Store(Running)
	proxies = map[string]C.Proxy{"handshake-budget": &handshakeBudgetProxy{dial: dial}}
	done := make(chan struct{})
	metadata := &C.Metadata{Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("203.0.113.80"), DstPort: 443, SpecialProxy: "handshake-budget"}
	go func() { handleTCPConn(icontext.NewConnContext(front, metadata)); close(done) }()
	t.Cleanup(func() {
		defer func() { status.Store(oldStatus); proxies = oldProxies }()
		peer.Close()
		front.Close()
		handshakeBudgetWait(t, done, C.DefaultTCPTimeout+2*time.Second)
	})
	if payload != "" {
		peer.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(peer, payload); err != nil {
			t.Fatal(err)
		}
		peer.SetWriteDeadline(time.Time{})
	}
	return peer, done
}

func TestDeferredHandshakeSilentWebSocketBudget(t *testing.T) {
	for _, payload := range []string{"", "hello"} {
		name := "empty-early-data"
		if payload != "" {
			name = "buffered-early-data"
		}
		t.Run(name, func(t *testing.T) {
			raw, server := net.Pipe()
			defer server.Close()
			requestRead, serverDone := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(serverDone)
				reader := bufio.NewReader(server)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				close(requestRead)
				io.Copy(io.Discard, reader) // Never send the HTTP 101 response.
			}()
			_, done := startHandshakeBudget(t, payload, func(context.Context) (C.Conn, error) {
				ws, err := vmess.StreamWebsocketConn(context.Background(), raw, &vmess.WebsocketConfig{Host: "handshake.invalid", Port: "80", Path: "/", Headers: http.Header{}, MaxEarlyData: 128, EarlyDataHeaderName: "Sec-WebSocket-Protocol"})
				if err != nil {
					return nil, err
				}
				return &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(ws), early: true}, nil
			})
			handshakeBudgetWait(t, requestRead, time.Second)
			handshakeBudgetWait(t, done, C.DefaultTCPTimeout+2*time.Second)
			handshakeBudgetWait(t, serverDone, time.Second)
		})
	}
}

func TestDeferredHandshakeWebSocketWinnerLifetime(t *testing.T) {
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		conn, err := vmess.StreamUpgradedWebsocketConn(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}))
	defer server.Close()
	raw, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	budgets := make(chan context.Context, 1)
	peer, done := startHandshakeBudget(t, "hello", func(ctx context.Context) (C.Conn, error) {
		select {
		case budgets <- ctx:
		default:
		}
		conn, err := vmess.StreamWebsocketConn(ctx, raw, &vmess.WebsocketConfig{Host: "handshake.invalid", Port: "80", Path: "/", Headers: http.Header{}, MaxEarlyData: 128, EarlyDataHeaderName: "Sec-WebSocket-Protocol"})
		if err != nil {
			return nil, err
		}
		return &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(conn), early: true}, nil
	})
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "hello" {
		t.Fatalf("WebSocket Upgrade/early data: %q %v", got, err)
	}
	budget := <-budgets
	handshakeBudgetWait(t, budget.Done(), C.DefaultTCPTimeout+2*time.Second)
	if budget.Err() != context.DeadlineExceeded {
		t.Fatalf("dial budget: %v", budget.Err())
	}
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(peer, "again"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "again" {
		t.Fatalf("dial budget interrupted established WebSocket: %q %v", got, err)
	}
	peer.Close()
	handshakeBudgetWait(t, done, 2*time.Second)
	handshakeBudgetWait(t, serverDone, 2*time.Second)
}

func TestDeferredHandshakeLateDialSuccessClosed(t *testing.T) {
	raw, server := net.Pipe()
	defer server.Close()
	late := &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(raw), closed: make(chan struct{})}
	_, done := startHandshakeBudget(t, "", func(ctx context.Context) (C.Conn, error) {
		<-ctx.Done()
		return late, nil // Adapter returns a successful connection after its budget.
	})
	handshakeBudgetWait(t, done, C.DefaultTCPTimeout+2*time.Second)
	handshakeBudgetWait(t, late.closed, time.Second)
}

func TestDeferredHandshakeLateWriteSuccessClosed(t *testing.T) {
	raw, server := net.Pipe()
	defer server.Close()
	late := &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(raw), early: true, closed: make(chan struct{})}
	defer late.Close()
	late.write = func(b []byte) (int, error) { <-late.closed; return len(b), nil }
	_, done := startHandshakeBudget(t, "hello", func(context.Context) (C.Conn, error) { return late, nil })
	handshakeBudgetWait(t, done, C.DefaultTCPTimeout+2*time.Second)
	handshakeBudgetWait(t, late.closed, time.Second)
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("late write winner was not closed: %v", err)
	}
}

func TestDeferredHandshakeRetryAndWinnerLifetime(t *testing.T) {
	for _, early := range []bool{false, true} {
		name := "ordinary"
		if early {
			name = "early-retry"
		}
		t.Run(name, func(t *testing.T) {
			raw, server := net.Pipe()
			defer server.Close()
			serverDone := make(chan struct{})
			go func() { io.Copy(server, server); close(serverDone) }()
			var calls atomic.Int32
			var failed *handshakeBudgetConn
			if early {
				a, b := net.Pipe()
				defer b.Close()
				failed = &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(a), early: true, closed: make(chan struct{}), write: func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }}
			}
			peer, _ := startHandshakeBudget(t, "hello", func(context.Context) (C.Conn, error) {
				if calls.Add(1) == 1 && early {
					return failed, nil
				}
				return &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(raw), early: early}, nil
			})
			peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			got := make([]byte, 5)
			if _, err := io.ReadFull(peer, got); err != nil || string(got) != "hello" {
				t.Fatalf("buffered payload changed across retry: %q %v", got, err)
			}
			if early {
				handshakeBudgetWait(t, failed.closed, time.Second)
				if calls.Load() != 2 {
					t.Fatalf("dial attempts=%d", calls.Load())
				}
			}
			time.Sleep(C.DefaultTCPTimeout + 100*time.Millisecond)
			peer.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.WriteString(peer, "again"); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(peer, got); err != nil || string(got) != "again" {
				t.Fatalf("dial timer interrupted relay: %q %v", got, err)
			}
			peer.Close()
			handshakeBudgetWait(t, serverDone, time.Second)
		})
	}
}

func TestDeferredHandshakeFrontendHalfClose(t *testing.T) {
	// A native TCP backend gives Relay a real CloseWrite capability.
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	outbound, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		outbound.Close()
		t.Fatal(err)
	}
	defer server.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		request, err := io.ReadAll(server)
		if err == nil {
			server.Write(request)
		}
		server.CloseWrite()
	}()
	peer, done := startHandshakeBudget(t, "hello", func(context.Context) (C.Conn, error) {
		return &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(outbound), early: true}, nil
	})
	peer.CloseWrite()
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "hello" {
		t.Fatalf("FIN discarded reverse response: %q %v", got, err)
	}
	handshakeBudgetWait(t, serverDone, time.Second)
	handshakeBudgetWait(t, done, time.Second)
}

func TestDeferredHandshakeRejectDoesNotRetry(t *testing.T) {
	raw, server := net.Pipe()
	defer server.Close()
	rejected := &handshakeBudgetConn{ExtendedConn: N.NewExtendedConn(raw), early: true, reject: true, closed: make(chan struct{}), write: func([]byte) (int, error) { return 0, io.ErrClosedPipe }}
	var calls atomic.Int32
	_, done := startHandshakeBudget(t, "hello", func(context.Context) (C.Conn, error) { calls.Add(1); return rejected, nil })
	handshakeBudgetWait(t, done, 2*time.Second)
	handshakeBudgetWait(t, rejected.closed, time.Second)
	if calls.Load() != 1 {
		t.Fatalf("REJECT retried %d times", calls.Load())
	}
}
