package miu

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
	"github.com/metacubex/tls"
)

// End-to-end loopback: Client → Server → target, all in this process. The outer layer is TLS, uTLS with
// a browser fingerprint, or — for a few light tests — plaintext TCP (no raw segments, everything in
// DATA). With a real TLS 1.3 connection inside, raw segments are used — and the inner TLS's integrity
// check is the referee: one byte lost or misplaced on the way in or out of a raw segment and the inner
// connection fails.

const testPSK = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ="

var testCert = func() tls.Certificate {
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		panic(err)
	}
	cert, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		panic(err)
	}
	return cert
}()

// collectEvents gathers what the test hook reports (lanes dialed and reused, raw segments sent, …).
func collectEvents(t *testing.T) func(string) int {
	t.Helper()
	var mu sync.Mutex
	events := map[string]int{}
	f := func(e string) {
		mu.Lock()
		events[e]++
		mu.Unlock()
	}
	testObserver.Store(&f)
	t.Cleanup(func() { testObserver.Store(nil) })
	return func(e string) int {
		mu.Lock()
		defer mu.Unlock()
		return events[e]
	}
}

// eventually polls cond for a few seconds: what follows the end of a stream (the abort that returns its
// lane to the pool, a warm-up dial) happens in the background.
func eventually(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// embeddedConn stands in for the wrappers that embed a TLS connection, like the REALITY listener's.
type embeddedConn struct{ *tls.Conn }

type pairOptions struct {
	outer     string // "" (plaintext), "tls", "utls" or "embedded" (TLS, wrapped on the server side)
	psk       string // the client's; the server always has testPSK
	server    ServerConfig
	client    ClientConfig
	serveErrs chan error
}

// relay is the handler of the test server: it connects the stream to its destination, the way the
// tunnel does for a listener.
func relay(ctx context.Context, conn net.Conn, user string, destination M.Socksaddr) {
	var target net.Conn
	if isUoT(destination) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return
		}
		target = uot.NewServerConn(pc, uot.Version)
	} else {
		var err error
		target, err = (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", destination.String())
		if err != nil {
			return
		}
	}
	N.Relay(conn, target)
}

// startServer runs a server on a loopback port and returns its address.
func startServer(t *testing.T, o pairOptions) string {
	t.Helper()
	cfg := o.server
	cfg.Users = map[string]string{"test": testPSK}
	if cfg.Handler == nil {
		cfg.Handler = relay
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ln.Close() })
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{testCert}, MinVersion: tls.VersionTLS13, DynamicRecordSizingDisabled: true}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if o.outer != "" {
					tc := tls.Server(conn, tlsConfig)
					if err := tc.HandshakeContext(ctx); err != nil {
						conn.Close()
						return
					}
					conn = tc
					if o.outer == "embedded" {
						conn = embeddedConn{tc}
					}
				}
				err := srv.Serve(ctx, conn)
				if o.serveErrs != nil {
					o.serveErrs <- err
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// outerDialer returns a ClientConfig.Dial that connects to addr and puts the outer layer on top. wrap,
// if not nil, goes between the TCP connection and that layer.
func outerDialer(addr, outer string, wrap func(net.Conn) net.Conn) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, DynamicRecordSizingDisabled: true}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		if wrap != nil {
			conn = wrap(conn)
		}
		var outerConn interface {
			net.Conn
			HandshakeContext(ctx context.Context) error
		}
		switch outer {
		case "":
			return conn, nil
		case "utls":
			chrome, _ := tlsC.GetFingerprint("chrome")
			outerConn = tlsC.UClient(conn, tlsC.UConfig(tlsConfig), chrome)
		default:
			outerConn = tls.Client(conn, tlsConfig)
		}
		if err := outerConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return outerConn, nil
	}
}

// pair starts a server and returns a client for it.
func pair(t *testing.T, o pairOptions) *Client {
	t.Helper()
	cfg := o.client
	cfg.PSK = testPSK
	if o.psk != "" {
		cfg.PSK = o.psk
	}
	cfg.Dial = outerDialer(startServer(t, o), o.outer, nil)
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func dial(t *testing.T, c *Client, target string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, M.ParseSocksaddr(target))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func closeWrite(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
}

func listen(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().String()
}

func echoTCP(t *testing.T) string {
	return listen(t, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
}

// innerTLS returns a TLS 1.3 server config and the matching client wrapper for the inner connection.
func innerTLS() (*tls.Config, func(net.Conn) net.Conn) {
	server := &tls.Config{Certificates: []tls.Certificate{testCert}, MinVersion: tls.VersionTLS13}
	return server, func(raw net.Conn) net.Conn {
		return tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	}
}

// innerTLSEcho starts a real TLS 1.3 echo server; wrap is the inner TLS client for it.
func innerTLSEcho(t *testing.T) (string, func(net.Conn) net.Conn) {
	t.Helper()
	cfg, wrap := innerTLS()
	return listen(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		defer tc.Close()
		_, _ = io.Copy(tc, tc)
	}), wrap
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// roundTrip sends payload to an echo target and reads the same bytes back, then ends the stream in an
// orderly way so that its lane goes back to the pool. wrap, if not nil, puts the inner TLS on top.
func roundTrip(t *testing.T, c *Client, target string, payload []byte, wrap func(net.Conn) net.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := c.DialContext(ctx, M.ParseSocksaddr(target))
	if err != nil {
		t.Error(err)
		return
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	conn := raw
	if wrap != nil {
		conn = wrap(raw)
	}
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Errorf("read echo (%d bytes): %v", len(payload), err)
		return
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch (%d bytes)", len(payload))
		return
	}
	// Half-close, read the other direction to its end: both directions END, the lane is pooled.
	if tc, ok := conn.(*tls.Conn); ok {
		_ = tc.CloseWrite()
		_, _ = io.Copy(io.Discard, tc)
	}
	if err := raw.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v", err)
		return
	}
	if n, err := io.Copy(io.Discard, raw); err != nil || n != 0 {
		t.Errorf("after the echo: %d stray bytes, %v", n, err)
	}
}

// exercise: a small payload, a large one, concurrent streams, then a few one after another (those
// should reuse lanes the earlier ones put back).
func exercise(t *testing.T, c *Client, target string, wrap func(net.Conn) net.Conn) {
	t.Helper()
	roundTrip(t, c, target, []byte("hello miu"), wrap)
	roundTrip(t, c, target, random(512<<10), wrap)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			roundTrip(t, c, target, random(64<<10+i), wrap)
		}(i)
	}
	wg.Wait()
	for i := 0; i < 6; i++ {
		roundTrip(t, c, target, random(1000+i), wrap)
	}
}

// Plaintext outer layer: neither side can use raw segments, everything travels in DATA frames — even a
// TLS 1.3 connection inside. Nothing runs Miu over plain TCP outside of these tests, and reading frames
// straight off a socket takes a system call for every frame header, so the traffic is kept light.
func TestLoopbackPlain(t *testing.T) {
	count := collectEvents(t)
	c := pair(t, pairOptions{})
	target, wrap := innerTLSEcho(t)
	for i := 0; i < 6; i++ {
		roundTrip(t, c, target, random(8<<10+i), wrap)
	}
	if n := count("client:raw") + count("server:raw"); n != 0 {
		t.Fatalf("raw segments on a plaintext outer transport: %d", n)
	}
	if count("client:reuse") == 0 {
		t.Fatalf("lanes were never reused (dial=%d)", count("client:dial"))
	}
}

// Outer TLS, inner data that is not TLS: the plaintext has to stay inside the outer encryption.
func TestLoopbackTLSPlainInner(t *testing.T) {
	count := collectEvents(t)
	exercise(t, pair(t, pairOptions{outer: "tls"}), echoTCP(t), nil)
	if n := count("client:raw") + count("server:raw"); n != 0 {
		t.Fatalf("non-TLS inner data left the outer TLS: %d raw segments", n)
	}
	if count("client:reuse") == 0 {
		t.Fatalf("lanes were never reused (dial=%d)", count("client:dial"))
	}
}

// Outer TLS, inner real TLS 1.3: after the inner handshake both directions use raw segments, and lanes
// are reused between streams (the same outer connection goes in and out of raw segments again and again).
func TestRawSegmentsInnerTLS(t *testing.T) {
	for _, outer := range []string{"tls", "utls", "embedded"} {
		t.Run(outer, func(t *testing.T) {
			count := collectEvents(t)
			target, wrap := innerTLSEcho(t)
			exercise(t, pair(t, pairOptions{outer: outer}), target, wrap)
			if count("client:raw") == 0 || count("server:rawin") == 0 {
				t.Fatal("the uplink never used raw segments")
			}
			if count("server:raw") == 0 || count("client:rawin") == 0 {
				t.Fatal("the downlink never used raw segments")
			}
			if count("client:reuse") == 0 {
				t.Fatalf("lanes were never reused (dial=%d)", count("client:dial"))
			}
		})
	}
}

// Streams one after another run on the same lane: after the first handshake (and the two lanes warmed
// up in the background) nothing is dialed any more, raw segments or not.
func TestSequentialStreamsShareLane(t *testing.T) {
	count := collectEvents(t)
	target, wrap := innerTLSEcho(t)
	c := pair(t, pairOptions{outer: "tls"})
	const streams = 12
	for i := 0; i < streams; i++ {
		roundTrip(t, c, target, random(64<<10), wrap)
	}
	if dials, reuse := count("client:dial"), count("client:reuse"); dials > 3 || reuse < streams-1 {
		t.Fatalf("dials=%d reuse=%d for %d consecutive streams", dials, reuse, streams)
	}
	if count("client:raw") < streams || count("server:raw") < streams {
		t.Fatalf("raw segments: up %d, down %d", count("client:raw"), count("server:raw"))
	}
}

// A side that has raw segments turned off neither receives nor sends any: it has no access to the socket.
func TestRawDisabled(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			count := collectEvents(t)
			o := pairOptions{outer: "tls"}
			if side == "client" {
				o.client.DisableRaw = true
			} else {
				o.server.DisableRaw = true
			}
			target, wrap := innerTLSEcho(t)
			c := pair(t, o)
			roundTrip(t, c, target, random(256<<10), wrap)
			roundTrip(t, c, target, random(256<<10), wrap)
			if count("client:raw")+count("server:raw") != 0 {
				t.Fatalf("raw segments with %s raw disabled (up %d, down %d)", side, count("client:raw"), count("server:raw"))
			}
		})
	}
}

// UDP travels over a stream as UoT; the session ends by abort and its lane is used again by the next.
func TestLoopbackUDP(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(b[:n], from)
		}
	}()
	count := collectEvents(t)
	c := pair(t, pairOptions{outer: "tls"})

	const rounds = 3
	for round := 0; round < rounds; round++ {
		conn := dial(t, c, uot.RequestDestination(uot.Version).String())
		pc := uot.NewLazyConn(conn, uot.Request{Destination: M.SocksaddrFromNet(echo.LocalAddr())})
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
		// Up to what a loopback datagram may carry on every platform.
		for i, size := range []int{1, 500, 1400, 9000} {
			msg := append([]byte(fmt.Sprintf("udp packet %d.%d ", round, i)), random(size)...)
			if _, err := pc.WriteTo(msg, echo.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 65535)
			n, from, err := pc.ReadFrom(got)
			if err != nil {
				t.Fatalf("udp echo %d.%d: %v", round, i, err)
			}
			if !bytes.Equal(got[:n], msg) {
				t.Fatalf("udp echo %d.%d mismatch (%d bytes of %d)", round, i, n, len(msg))
			}
			if from.String() != echo.LocalAddr().String() {
				t.Fatalf("source %v, want %v", from, echo.LocalAddr())
			}
		}
		pc.Close()
		if !eventually(func() bool { return count("client:reset") == round+1 }) {
			t.Fatalf("round %d: the session did not end by abort (resets=%d)", round, count("client:reset"))
		}
	}
	if count("client:reuse") < rounds-1 || count("client:raw")+count("server:raw") != 0 {
		t.Fatalf("resets=%d reuse=%d dials=%d", count("client:reset"), count("client:reuse"), count("client:dial"))
	}
}

func TestRejectBadCredential(t *testing.T) {
	// Garbage instead of a token: the server closes the connection.
	errs := make(chan error, 4)
	addr := startServer(t, pairOptions{serveErrs: errs})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(random(120))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("server should close on a bad credential")
	}
	if err := <-errs; !errors.Is(err, ErrAuth) {
		t.Fatalf("Serve returned %v", err)
	}

	// A client with the wrong PSK: the stream fails, it does not look like an orderly end.
	for _, outer := range []string{"", "tls"} {
		c := pair(t, pairOptions{outer: outer, psk: "this-is-not-the-right-psk"})
		conn := dial(t, c, echoTCP(t))
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("hello"))
		if n, err := conn.Read(make([]byte, 16)); err == nil || err == io.EOF {
			t.Fatalf("outer %q: read with a wrong psk: %d bytes, %v", outer, n, err)
		}
		conn.Close()
	}

	if _, err := NewClient(ClientConfig{PSK: "short", Dial: outerDialer(addr, "", nil)}); err == nil {
		t.Fatal("a short psk was accepted")
	}
	if _, err := NewClient(ClientConfig{PSK: testPSK}); err == nil {
		t.Fatal("a client without a dialer was accepted")
	}
	if _, err := NewServer(ServerConfig{Users: map[string]string{"a": testPSK, "b": " " + testPSK}, Handler: relay}); err == nil {
		t.Fatal("two users with the same psk were accepted")
	}
	if _, err := NewServer(ServerConfig{Users: map[string]string{"a": "short"}, Handler: relay}); err == nil {
		t.Fatal("a user with a short psk was accepted")
	}
	if _, err := NewServer(ServerConfig{Handler: relay}); err == nil {
		t.Fatal("a server without users was accepted")
	}
	if _, err := NewServer(ServerConfig{Users: map[string]string{"a": testPSK}}); err == nil {
		t.Fatal("a server without a handler was accepted")
	}
}

// The handler is told who opened the stream and where it should go.
func TestHandlerArguments(t *testing.T) {
	type call struct {
		user        string
		destination M.Socksaddr
	}
	calls := make(chan call, 4)
	c := pair(t, pairOptions{outer: "tls", server: ServerConfig{Handler: func(ctx context.Context, conn net.Conn, user string, destination M.Socksaddr) {
		calls <- call{user, destination}
	}}})
	for _, target := range []string{"example.com:443", "127.0.0.1:80", "[2001:db8::1]:8443"} {
		conn := dial(t, c, target)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		// The handler returns at once: the stream ends without a byte.
		if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("%s: read %d %v", target, n, err)
		}
		conn.Close()
		if got := <-calls; got.user != "test" || got.destination.String() != target {
			t.Fatalf("handler called with user %q, destination %v", got.user, got.destination)
		}
	}
}

// foreverTCP starts a server that keeps writing, at a steady pace, for as long as the peer reads. With
// withTLS it speaks TLS 1.3. open counts the connections that are still open.
//
// The pace keeps the reader ahead of the writer. A download that outruns its reader over loopback
// keeps the socket buffers full, and recent Linux kernels can answer that by shrinking the receive
// buffer to a single segment: the connection then crawls from one zero-window probe to the next, for
// longer than these tests wait. For the same reason the payloads of the other tests are modest.
func foreverTCP(t *testing.T, withTLS bool) (addr string, wrap func(net.Conn) net.Conn, open *atomic.Int32) {
	t.Helper()
	open = new(atomic.Int32)
	wrap = func(c net.Conn) net.Conn { return c }
	var cfg *tls.Config
	if withTLS {
		cfg, wrap = innerTLS()
	}
	chunk := random(32 << 10)
	addr = listen(t, func(c net.Conn) {
		open.Add(1)
		defer open.Add(-1)
		defer c.Close()
		if cfg != nil {
			c = tls.Server(c, cfg)
		}
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	return addr, wrap, open
}

// Aborting a stream in the middle of a download: the client sends RESET, the server stops the downlink
// and closes it with END, and the lane goes back to the pool for the next stream — an abort must not
// cost a lane. This has to hold while the stream is in DATA frames and once it is in raw segments.
func TestAbortKeepsLane(t *testing.T) {
	cases := []struct {
		name     string
		outer    string
		innerTLS bool
	}{
		{"data", "tls", false}, {"raw", "tls", true}, {"raw-utls", "utls", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			count := collectEvents(t)
			target, wrap, open := foreverTCP(t, tc.innerTLS)
			c := pair(t, pairOptions{outer: tc.outer})
			const rounds = 6
			for i := 0; i < rounds; i++ {
				raw := dial(t, c, target)
				_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
				if _, err := io.ReadFull(wrap(raw), make([]byte, 512<<10)); err != nil {
					t.Fatalf("round %d: %v", i, err)
				}
				raw.Close() // leave in the middle of the download
				// Every round is an abort, after which the lane is back in the pool.
				if !eventually(func() bool { return count("client:reset") == i+1 }) {
					t.Fatalf("round %d: resets=%d: the abort did not return the lane", i, count("client:reset"))
				}
			}
			// The lanes are the same few throughout (the first one and the two warmed up in the
			// background), not a new one per round.
			if dials := count("client:dial"); dials > 3 {
				t.Fatalf("dials=%d reuse=%d: aborted streams are burning lanes", dials, count("client:reuse"))
			}
			if tc.innerTLS != (count("server:raw") > 0) {
				t.Fatalf("inner TLS %v, but %d raw segments on the downlink", tc.innerTLS, count("server:raw"))
			}
			if !eventually(func() bool { return open.Load() == 0 }) {
				t.Fatalf("%d target connections left open after the aborts", open.Load())
			}
			// The lanes are clean: ordinary streams work on them afterwards.
			echo := echoTCP(t)
			for i := 0; i < 4; i++ {
				roundTrip(t, c, echo, random(100<<10), nil)
			}
			if dials := count("client:dial"); dials > 3 {
				t.Fatalf("dials=%d after the aborts", dials)
			}
		})
	}
}

// The other ways a stream gets aborted: closed before anything was sent, closed right after the request,
// closed after a half-close, closed while the handler has not started reading. None of them costs a lane.
func TestAbortVariants(t *testing.T) {
	count := collectEvents(t)
	target, _, open := foreverTCP(t, false)
	// A handler that sits on some streams for a while before relaying them: the dial of a slow target.
	slow := "192.0.2.1:9"
	c := pair(t, pairOptions{outer: "tls", server: ServerConfig{Handler: func(ctx context.Context, conn net.Conn, user string, destination M.Socksaddr) {
		if destination.String() == slow {
			time.Sleep(500 * time.Millisecond)
			return
		}
		relay(ctx, conn, user, destination)
	}}})
	// aborted waits for the abort that makes it n streams ended by RESET.
	aborted := func(n int) {
		t.Helper()
		if !eventually(func() bool { return count("client:reset") == n }) {
			t.Fatalf("resets=%d, want %d", count("client:reset"), n)
		}
	}

	conn := dial(t, c, target) // closed before OPEN went out: nothing is sent at all
	conn.Close()
	time.Sleep(100 * time.Millisecond)
	if count("client:reset") != 0 {
		t.Fatal("RESET for a stream that was never opened")
	}

	conn = dial(t, c, target) // closed right after the first write
	_, _ = conn.Write([]byte("x"))
	conn.Close()
	aborted(1)

	conn = dial(t, c, target) // half-closed, then closed: RESET follows END
	_, _ = conn.Write([]byte("x"))
	closeWrite(t, conn)
	_, _ = io.ReadFull(conn, make([]byte, 100<<10))
	conn.Close()
	aborted(2)

	conn = dial(t, c, slow) // closed while the handler is not reading yet
	_, _ = conn.Write([]byte("x"))
	time.Sleep(50 * time.Millisecond)
	conn.Close()
	aborted(3)

	conn = dial(t, c, target) // closed after OPEN went out on its own, without a byte written or read
	conn2 := dial(t, c, slow) // closed from another goroutine while a Read is blocked
	_, _ = conn2.Write([]byte("x"))
	done := make(chan error, 1)
	go func() { _, err := conn2.Read(make([]byte, 1)); done <- err }()
	time.Sleep(50 * time.Millisecond)
	conn2.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a Read interrupted by Close returned %v", err)
	}
	conn.Close()
	aborted(5)

	if dials := count("client:dial"); dials > 4 {
		t.Fatalf("dials=%d", dials)
	}
	if !eventually(func() bool { return open.Load() == 0 }) {
		t.Fatalf("%d target connections left open", open.Load())
	}
	roundTrip(t, c, echoTCP(t), random(10<<10), nil)
}

// flakyConn is a connection that can be made to die without its owner noticing — which is what a pooled
// lane that went dead looks like to the client: alive when it is taken from the pool (flakyConn offers
// nothing to probe), gone once the stream has been written to it.
type flakyConn struct {
	net.Conn
	gen int32
	f   *flaky
}

type flaky struct {
	gen atomic.Int32
	// Connections made before killBefore are dead: with swallow their writes vanish and the next read
	// fails, otherwise the write itself fails.
	killBefore atomic.Int32
	swallow    atomic.Bool
}

func (f *flaky) killAll(swallow bool) {
	f.swallow.Store(swallow)
	f.killBefore.Store(f.gen.Load() + 1)
}

func (f *flaky) wrap(conn net.Conn) net.Conn {
	return &flakyConn{Conn: conn, gen: f.gen.Add(1), f: f}
}

func (c *flakyConn) Write(p []byte) (int, error) {
	if c.gen < c.f.killBefore.Load() {
		c.Conn.Close()
		if c.f.swallow.Load() {
			return len(p), nil
		}
		return 0, errors.New("flaky: connection is gone")
	}
	return c.Conn.Write(p)
}

// A stream that lands on a dead pooled lane is replayed once on a new lane, and the application does not
// notice. Not so once it has sent more than the replay limit, or when the lane was not from the pool.
func TestReplayOnDeadLane(t *testing.T) {
	count := collectEvents(t)
	f := &flaky{}
	addr := startServer(t, pairOptions{outer: "tls"})
	c, err := NewClient(ClientConfig{PSK: testPSK, Dial: outerDialer(addr, "tls", f.wrap)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	target, wrap := innerTLSEcho(t)
	echo := echoTCP(t)
	// kill makes every lane dialed so far dead. Warm-up dials are let finish first: a dead lane that
	// reached the pool only after a replay has cleared it would cause one more replay later on.
	kill := func(swallow bool) {
		t.Helper()
		warming := func() bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.pending > 0
		}
		if !eventually(func() bool { return !warming() }) {
			t.Fatal("warm-up dials did not finish")
		}
		f.killAll(swallow)
	}

	// Detected by the reader (the write seemed to work), then by the writer.
	for i, swallow := range []bool{true, false} {
		roundTrip(t, c, target, random(300<<10), wrap) // leaves a lane in the pool
		kill(swallow)
		roundTrip(t, c, target, random(300<<10), wrap)
		if n := count("client:replay"); n != i+1 {
			t.Fatalf("swallow=%v: %d replays", swallow, n)
		}
	}
	if count("client:raw") == 0 || count("server:raw") == 0 {
		t.Fatal("no raw segments after a replay")
	}

	// The uplink had already ended when the lane turned out to be dead: END is replayed too.
	roundTrip(t, c, echo, []byte("warm"), nil)
	kill(true)
	conn := dial(t, c, echo)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte("ping"))
	closeWrite(t, conn)
	if got, err := io.ReadAll(conn); err != nil || string(got) != "ping" {
		t.Fatalf("after the replay of a half-closed stream: %q %v", got, err)
	}
	conn.Close()
	if n := count("client:replay"); n != 3 {
		t.Fatalf("%d replays", n)
	}

	// More than the limit already sent: no replay, the stream fails.
	sink := listen(t, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	roundTrip(t, c, echo, []byte("warm"), nil)
	conn = dial(t, c, sink)
	if _, err := conn.Write(random(100 << 10)); err != nil {
		t.Fatal(err)
	}
	kill(false)
	if _, err := conn.Write([]byte("more")); err == nil {
		t.Fatal("a write on a dead lane succeeded past the replay limit")
	}
	conn.Close()

	// A lane that was dialed for this stream: no replay either.
	c.closeIdle() // the kill above has let the warm-up dials land
	conn = dial(t, c, sink)
	kill(false)
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("a write on a dead fresh lane succeeded")
	}
	conn.Close()
	if n := count("client:replay"); n != 3 {
		t.Fatalf("%d replays, want 3", n)
	}
	// And the client recovers.
	roundTrip(t, c, echo, random(10<<10), nil)
}

// A target that cannot be reached: the downlink ends at once, and the lane stays usable.
func TestUnreachableTarget(t *testing.T) {
	count := collectEvents(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	c := pair(t, pairOptions{outer: "tls"})
	for i := 0; i < 3; i++ {
		conn := dial(t, c, closed)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		if n, err := conn.Read(make([]byte, 16)); n != 0 || err != io.EOF {
			t.Fatalf("read from an unreachable target: %d %v", n, err)
		}
		closeWrite(t, conn)
		conn.Close()
	}
	if dials := count("client:dial"); dials > 3 || count("client:reuse") < 2 {
		t.Fatalf("dials=%d reuse=%d", dials, count("client:reuse"))
	}
	roundTrip(t, c, echoTCP(t), random(10<<10), nil)
}

// A protocol in which the server speaks first: OPEN must not wait for the client's first bytes.
// And a half-close: the target answers only after it has seen the end of the request.
func TestServerFirstAndHalfClose(t *testing.T) {
	c := pair(t, pairOptions{outer: "tls"})
	greeter := listen(t, func(c net.Conn) {
		defer c.Close()
		_, _ = c.Write([]byte("220 hello\r\n"))
		_, _ = io.Copy(io.Discard, c)
	})
	conn := dial(t, c, greeter)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 11)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "220 hello\r\n" {
		t.Fatalf("greeting: %q %v", got, err)
	}
	conn.Close()

	summer := listen(t, func(c net.Conn) {
		defer c.Close()
		h := sha256.New()
		_, _ = io.Copy(h, c) // reads to the end of the request
		_, _ = c.Write(h.Sum(nil))
	})
	payload := random(256 << 10)
	conn = dial(t, c, summer)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	closeWrite(t, conn)
	sum, err := io.ReadAll(conn)
	if want := sha256.Sum256(payload); err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("digest after the half-close: %x %v", sum, err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("write after CloseWrite succeeded")
	}
}

// retryConn reads with a short deadline and retries when it passes.
type retryConn struct {
	net.Conn
	timeouts *atomic.Int32
}

func (r retryConn) Read(p []byte) (int, error) {
	for {
		_ = r.Conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, err := r.Conn.Read(p)
		if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			r.timeouts.Add(1)
			continue
		}
		return n, err
	}
}

// A read deadline that passes leaves the stream intact: the read is simply retried. The inner TLS
// connection reads through deadlines that keep expiring, in the DATA phase and in raw segments alike,
// and still verifies every record.
func TestReadDeadlineIsResumable(t *testing.T) {
	cfg, _ := innerTLS()
	payload := random(600 << 10)
	target := listen(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		defer tc.Close()
		// In pieces, with pauses that let the client's deadline pass in between.
		for i := 0; i < len(payload); i += 50 << 10 {
			time.Sleep(30 * time.Millisecond)
			if _, err := tc.Write(payload[i:minInt(i+50<<10, len(payload))]); err != nil {
				return
			}
		}
	})
	count := collectEvents(t)
	c := pair(t, pairOptions{outer: "tls"})
	raw := dial(t, c, target)
	defer raw.Close()
	var timeouts atomic.Int32
	conn := tls.Client(retryConn{raw, &timeouts}, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("after %d timeouts: %v", timeouts.Load(), err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if timeouts.Load() < 5 || count("server:raw") == 0 {
		t.Fatalf("timeouts=%d raw=%d: the test did not exercise what it is for", timeouts.Load(), count("server:raw"))
	}
}

// Many streams at once: each has a lane to itself, and afterwards the pool holds them for reuse.
func TestConcurrentStreams(t *testing.T) {
	count := collectEvents(t)
	target, wrap := innerTLSEcho(t)
	c := pair(t, pairOptions{outer: "tls"})
	for round := 0; round < 2; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				roundTrip(t, c, target, random(64<<10+i), wrap)
			}(i)
		}
		wg.Wait()
	}
	if dials, reuse := count("client:dial"), count("client:reuse"); dials > 40 || reuse < 24 {
		t.Fatalf("dials=%d reuse=%d", dials, reuse)
	}
}

// The server closes a lane that has been idle for too long; the client notices when it next reaches for
// it and dials a new one, without the application seeing anything.
func TestServerIdleTimeout(t *testing.T) {
	count := collectEvents(t)
	echo := echoTCP(t)
	c := pair(t, pairOptions{outer: "tls", server: ServerConfig{IdleTimeout: time.Second}})
	roundTrip(t, c, echo, []byte("one"), nil)
	time.Sleep(1500 * time.Millisecond)
	roundTrip(t, c, echo, []byte("two"), nil)
	if dials := count("client:dial"); dials < 2 {
		t.Fatalf("dials=%d: the idle lane was not closed by the server", dials)
	}
}

// The server pushes its padding scheme when the client's differs; the stream works either way.
func TestServerPaddingScheme(t *testing.T) {
	c := pair(t, pairOptions{outer: "tls", server: ServerConfig{PaddingScheme: "stop=3\n0=40-60\n1=200-300\n2=300-400,c,600-700"}})
	echo := echoTCP(t)
	for i := 0; i < 3; i++ {
		roundTrip(t, c, echo, random(5000), nil)
	}
	if _, err := NewServer(ServerConfig{Users: map[string]string{"a": testPSK}, Handler: relay, PaddingScheme: "nonsense"}); err == nil {
		t.Fatal("a bad padding scheme was accepted")
	}
}
