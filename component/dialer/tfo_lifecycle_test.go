package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/tfo-go"
)

// Use the production TFO dialer and SOCKS5 handshake with a loopback peer.
// Unlike the late-success fault injection, no dial function is replaced here.
func TestLifecycleTFORealSOCKS5Cancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	greeting := make(chan []byte, 1)
	serverDone := make(chan error, 1)
	go func() {
		server, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		data := make([]byte, 3)
		if _, err = io.ReadFull(server, data); err != nil {
			serverDone <- err
			return
		}
		greeting <- data
		_, err = server.Read(make([]byte, 1)) // Withhold the method selection.
		serverDone <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := dialTFO(ctx, net.Dialer{}, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	finished := make(chan error, 1)
	go func() {
		var err error
		func() {
			done := N.SetupContextForConn(ctx, conn)
			defer done(&err)
			_, err = socks5.ClientHandshake(conn, socks5.ParseAddr("192.0.2.80:443"), socks5.CmdConnect, nil)
		}()
		finished <- err
	}()
	select {
	case data := <-greeting:
		if string(data) != "\x05\x01\x00" {
			t.Fatalf("unexpected SOCKS5 greeting: %x", data)
		}
	case err = <-finished:
		if errors.Is(err, tfo.ErrUnsupported) && os.Getenv("MIHOMO_TEST_TFO_REQUIRED") != "1" {
			t.Skipf("kernel/platform does not support TFO: %v", err)
		}
		t.Fatalf("real SOCKS5 handshake ended before its greeting: %v", err)
	case <-time.After(time.Second):
		t.Fatal("real lazy TFO handshake did not reach the peer")
	}
	cancel()
	select {
	case err = <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handshake after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("real SOCKS5 cancellation exceeded its bound")
	}
	select {
	case err = <-serverDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("canceled socket peer did not receive EOF: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("real TFO socket remained open")
	}
}

func TestLifecycleTFOCloseRetiresLateDialSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	raw, peer := net.Pipe()
	defer peer.Close()
	c := tfoTestConnection(t, ctx, cancel, func(context.Context, []byte) (net.Conn, error) {
		close(entered)
		<-release // Deliberately return success after observing cancellation.
		return raw, nil
	})
	writeDone := make(chan error, 1)
	go func() { _, err := c.Write([]byte("hello")); writeDone <- err }()
	tfoTestWait(t, entered)
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked waiting for dial")
	}
	close(release)
	select {
	case err := <-writeDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("late dial did not retire")
	}
	if c.Upstream() != nil {
		t.Fatal("closed wrapper published late success")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late socket not closed: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleTFOConcurrentMethodsAndFirstWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, peer := net.Pipe()
	defer peer.Close()
	c := tfoTestConnection(t, ctx, cancel, func(context.Context, []byte) (net.Conn, error) { return raw, nil })
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 20; j++ {
				c.LocalAddr()
				c.RemoteAddr()
				c.Upstream()
				c.NeedHandshake()
				c.ReaderReplaceable()
				c.WriterReplaceable()
				c.NeedAdditionalReadDeadline()
				_ = c.SetDeadline(time.Now().Add(time.Second))
			}
		}()
	}
	group.Add(2)
	go func() { defer group.Done(); _, _ = c.Write([]byte("first")) }()
	go func() { defer group.Done(); _ = c.Close() }()
	group.Wait()
}

func TestLifecycleTFOFirstWritersShareOneDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, peer := net.Pipe()
	defer peer.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	early := make(chan string, 1)
	var calls atomic.Int32
	c := tfoTestConnection(t, ctx, cancel, func(_ context.Context, data []byte) (net.Conn, error) {
		calls.Add(1)
		early <- string(data)
		close(entered)
		<-release
		return raw, nil
	})
	defer c.Close()
	writes := make(chan error, 2)
	go func() { _, err := c.Write([]byte("one")); writes <- err }()
	tfoTestWait(t, entered)
	go func() { _, err := c.Write([]byte("two")); writes <- err }()
	close(release)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 3)
	if _, err := io.ReadFull(peer, data); err != nil {
		t.Fatal(err)
	}
	if first := <-early; first != "one" || string(data) != "two" || calls.Load() != 1 {
		t.Fatalf("early=%q subsequent=%q dials=%d", first, data, calls.Load())
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-writes:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("first writer did not finish")
		}
	}
}

// Use the production lazy constructor so the same fixture also builds before
// synchronization is added. No network operation occurs until the fake dial.
func tfoTestConnection(t *testing.T, ctx context.Context, cancel context.CancelFunc, dial func(context.Context, []byte) (net.Conn, error)) *tfoConn {
	t.Helper()
	conn, err := dialTFO(context.Background(), net.Dialer{}, "tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*tfoConn)
	c.cancel()
	c.ctx, c.cancel, c.dialFn = ctx, cancel, dial
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func tfoTestWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dial was not entered")
	}
}
