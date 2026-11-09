package tunnel

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/http"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mipstack"
)

// Packet bridging exercises actual forwarded native TCP endpoints. No fake
// CancelOnClose source or injected callback is used. Route selection alone is
// replaced to isolate the tunnel's preparation lifecycle.
func lifecycleNativeFrontend(t *testing.T, dial func(context.Context) (C.Conn, error)) (net.Conn, *mipstack.TCPConn, <-chan struct{}) {
	t.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.10")
	client, err := mipstack.New(mipstack.Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(clientAddress, 32)}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := mipstack.New(mipstack.Config{Promiscuous: true, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, stack := range []*mipstack.Stack{client, server} {
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		conn *mipstack.TCPConn
		err  error
	}
	accepted := make(chan result, 1)
	forwarder, err := mipstack.NewTCPForwarder(server, mipstack.TCPForwarderOptions{}, func(request *mipstack.TCPForwarderRequest) {
		conn, acceptErr := request.Accept(ctx)
		accepted <- result{conn, acceptErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close() })
	pumps := make(chan error, 2)
	for _, direction := range [][2]*mipstack.Stack{{client, server}, {server, client}} {
		from, to := direction[0], direction[1]
		go func() {
			buffers, sizes := [][]byte{make([]byte, 1500)}, make([]int, 1)
			for {
				n, readErr := from.Read(buffers, sizes, 0)
				if readErr != nil {
					pumps <- readErr
					return
				}
				if _, writeErr := to.Write([][]byte{buffers[0][:sizes[0]]}[:n], 0); writeErr != nil {
					pumps <- writeErr
					return
				}
			}
		}()
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-pumps:
			case <-time.After(time.Second):
				t.Error("native packet pump did not exit")
			}
		}
	})
	peer, err := client.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("198.51.100.80:443"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	var front *mipstack.TCPConn
	select {
	case r := <-accepted:
		if r.err != nil {
			t.Fatal(r.err)
		}
		front = r.conn
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = front.Close() })
	if _, ok := any(front).(interface {
		CancelOnClose(context.CancelFunc) func() bool
	}); !ok {
		if os.Getenv("MIHOMO_TEST_NATIVE_CLOSE_REQUIRED") == "1" {
			t.Fatal("native close API required by integration validation")
		}
		t.Skip("requires the proposed mipstack full-close API")
	}
	oldStatus, oldProxies := status.Load(), proxies
	status.Store(Running)
	proxies = map[string]C.Proxy{"lifecycle": &lifecycleProxy{dial: dial}}
	done := make(chan struct{})
	metadata := &C.Metadata{Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("198.51.100.80"), DstPort: 443, SpecialProxy: "lifecycle"}
	go func() { handleTCPConn(icontext.NewConnContext(front, metadata)); close(done) }()
	t.Cleanup(func() {
		_ = peer.Close()
		_ = front.Close()
		lifecycleWait(t, done, C.DefaultTCPTimeout+2*time.Second)
		status.Store(oldStatus)
		proxies = oldProxies
	})
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err = peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetWriteDeadline(time.Time{})
	return peer, front, done
}

func TestLifecycleNativeResetCancelsWebSocket(t *testing.T) {
	raw, server := net.Pipe()
	defer server.Close()
	requestRead := make(chan struct{})
	serverDone := make(chan struct{})
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
		_, _ = io.Copy(io.Discard, reader) // Real Upgrade; deliberately no HTTP 101.
	}()
	peer, _, done := lifecycleNativeFrontend(t, func(ctx context.Context) (C.Conn, error) {
		ws, err := vmess.StreamWebsocketConn(ctx, raw, &vmess.WebsocketConfig{Host: "native.invalid", Port: "80", Path: "/", Headers: http.Header{}, MaxEarlyData: 128, EarlyDataHeaderName: "Sec-WebSocket-Protocol"})
		if err != nil {
			return nil, err
		}
		return &lifecycleOutbound{ExtendedConn: N.NewExtendedConn(ws), early: true}, nil
	})
	lifecycleWait(t, requestRead, time.Second)
	if err := peer.(*mipstack.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("native peer reset sent after the HTTP Upgrade request was read")
	// A five-second generic budget cannot satisfy this assertion.
	lifecycleWait(t, done, time.Second)
	lifecycleWait(t, serverDone, time.Second)
}

func TestLifecycleNativeFINPreservesResponse(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	backend, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var dialCtx context.Context
	peer, front, done := lifecycleNativeFrontend(t, func(ctx context.Context) (C.Conn, error) {
		dialCtx = ctx
		close(entered)
		select {
		case <-release:
			return &lifecycleOutbound{ExtendedConn: N.NewExtendedConn(raw)}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	lifecycleWait(t, entered, time.Second)
	if err = peer.(*mipstack.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// Info is actor-serialized. Wait for actual FIN processing without racing
	// the tunnel's peek reader or consuming its request payload.
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for front.Info().State != mipstack.TCPStateCloseWait {
		select {
		case <-limit.C:
			t.Fatal("native peer FIN not observed")
		case <-tick.C:
		}
	}
	if err = dialCtx.Err(); err != nil {
		t.Fatalf("peer FIN canceled preparation: %v", err)
	}
	close(release)
	_ = backend.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := io.ReadAll(backend)
	if err != nil || string(request) != "hello" {
		t.Fatalf("request before FIN = %q, %v", request, err)
	}
	if _, err = backend.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err = backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := io.ReadAll(peer)
	if err != nil || string(response) != "response" {
		t.Fatalf("response after FIN = %q, %v", response, err)
	}
	lifecycleWait(t, done, time.Second)
}
