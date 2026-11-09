package tunnel

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/transport/vmess"
)

type lifecycleSource struct {
	net.Conn
	mu      sync.Mutex
	cancel  context.CancelFunc
	claimed bool
}

func (c *lifecycleSource) CancelOnClose(cancel context.CancelFunc) func() bool {
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.claimed || c.cancel == nil {
			return false
		}
		c.cancel = nil
		return true
	}
}

func (c *lifecycleSource) claim() context.CancelFunc {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.claimed = true
	cancel := c.cancel
	c.cancel = nil
	return cancel
}

type lifecycleProxy struct {
	C.Proxy
	dial func(context.Context) (C.Conn, error)
}

func (p *lifecycleProxy) Name() string { return "lifecycle" }
func (p *lifecycleProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	return p.dial(ctx)
}

type lifecycleOutbound struct {
	N.ExtendedConn
	early bool
}

func (c *lifecycleOutbound) NeedHandshake() bool           { return c.early }
func (c *lifecycleOutbound) Chains() C.Chain               { return C.Chain{"lifecycle"} }
func (c *lifecycleOutbound) ProviderChains() C.Chain       { return nil }
func (c *lifecycleOutbound) AppendToChains(C.ProxyAdapter) {}
func (c *lifecycleOutbound) RemoteDestination() string     { return "isolate.invalid" }

func lifecycleWait(t *testing.T, done <-chan struct{}, limit time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatal("connection lifecycle did not finish")
	}
}

func lifecycleStart(t *testing.T, capable bool, dial func(context.Context) (C.Conn, error)) (net.Conn, *lifecycleSource, <-chan struct{}) {
	t.Helper()
	oldStatus, oldProxies := status.Load(), proxies
	status.Store(Running)
	proxies = map[string]C.Proxy{"lifecycle": &lifecycleProxy{dial: dial}}
	front, peer := net.Pipe()
	source := &lifecycleSource{Conn: front}
	var input net.Conn = front
	if capable {
		input = source
	}
	done := make(chan struct{})
	metadata := &C.Metadata{Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("203.0.113.80"), DstPort: 443, SpecialProxy: "lifecycle"}
	go func() { handleTCPConn(icontext.NewConnContext(input, metadata)); close(done) }()
	t.Cleanup(func() {
		_ = peer.Close()
		_ = front.Close()
		lifecycleWait(t, done, 7*time.Second)
		status.Store(oldStatus)
		proxies = oldProxies
	})
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetWriteDeadline(time.Time{})
	return peer, source, done
}

func TestLifecycleCanceledDialClosesLateSuccess(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	entered := make(chan struct{})
	_, source, done := lifecycleStart(t, true, func(ctx context.Context) (C.Conn, error) {
		close(entered)
		<-ctx.Done()
		return &lifecycleOutbound{ExtendedConn: N.NewExtendedConn(raw)}, nil
	})
	lifecycleWait(t, entered, time.Second)
	cancel := source.claim()
	if cancel == nil {
		t.Fatal("wrapper traversal missed cancellation capability")
	}
	cancel()
	lifecycleWait(t, done, time.Second)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("late outbound not closed: %v", err)
	}
}

func TestLifecycleClaimedTerminationRejectsHandoffBeforeCancelRuns(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	_, source, done := lifecycleStart(t, true, func(context.Context) (C.Conn, error) {
		close(entered)
		<-release
		return &lifecycleOutbound{ExtendedConn: N.NewExtendedConn(raw)}, nil
	})
	lifecycleWait(t, entered, time.Second)
	cancel := source.claim()
	if cancel == nil {
		t.Fatal("missing cancellation registration")
	}
	// Native closure won but has not invoked cancel yet. ctx.Err is still nil.
	close(release)
	lifecycleWait(t, done, time.Second)
	cancel()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("claimed outbound reached relay: %v", err)
	}
}

func TestLifecycleWebSocketEarlyHandshakeCancellation(t *testing.T) {
	for _, capable := range []bool{true, false} {
		name := "dial-timeout-without-native-hook"
		if capable {
			name = "native-termination"
		}
		t.Run(name, func(t *testing.T) {
			raw, peer := net.Pipe()
			defer peer.Close()
			requestRead := make(chan struct{})
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				reader := bufio.NewReader(peer)
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
				_, _ = io.Copy(io.Discard, reader) // Deliberately never send HTTP 101.
			}()
			_, source, done := lifecycleStart(t, capable, func(context.Context) (C.Conn, error) {
				ws, err := vmess.StreamWebsocketConn(context.Background(), raw, &vmess.WebsocketConfig{Host: "isolate.invalid", Port: "80", Path: "/", Headers: http.Header{}, MaxEarlyData: 128, EarlyDataHeaderName: "Sec-WebSocket-Protocol"})
				if err != nil {
					return nil, err
				}
				return &lifecycleOutbound{ExtendedConn: N.NewExtendedConn(ws), early: true}, nil
			})
			lifecycleWait(t, requestRead, time.Second)
			if capable {
				source.claim()()
			}
			lifecycleWait(t, done, 7*time.Second)
			lifecycleWait(t, serverDone, time.Second)
		})
	}
}

func TestLifecycleSuccessfulEarlyConnectionSurvivesDialTimeout(t *testing.T) {
	raw, backend := net.Pipe()
	defer backend.Close()
	serverDone := make(chan struct{})
	go func() { _, _ = io.Copy(backend, backend); close(serverDone) }()
	peer, source, _ := lifecycleStart(t, true, func(context.Context) (C.Conn, error) {
		return &lifecycleOutbound{ExtendedConn: N.NewExtendedConn(raw), early: true}, nil
	})
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "hello" {
		t.Fatalf("first handshake: %q %v", got, err)
	}
	source.mu.Lock()
	retained := source.cancel != nil
	source.mu.Unlock()
	if retained {
		t.Fatal("handoff retained native cancellation registration")
	}
	time.Sleep(C.DefaultTCPTimeout + 100*time.Millisecond)
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "again" {
		t.Fatalf("dial timer closed a relay winner: %q %v", got, err)
	}
	_ = peer.Close()
	lifecycleWait(t, serverDone, time.Second)
}
