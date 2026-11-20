package miu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

// ---- helpers ----

func inTable(t []smallLen, n int) bool {
	for _, e := range t {
		if int(e.n) == n {
			return true
		}
	}
	return false
}

// frameTypes lists the frame types in b, PAD included.
func frameTypes(b []byte) []byte {
	var out []byte
	for len(b) >= frameHead {
		n := int(binary.BigEndian.Uint16(b[1:]))
		out = append(out, b[0])
		if len(b) < frameHead+n {
			break
		}
		b = b[frameHead+n:]
	}
	return out
}

func withoutPad(types []byte) []byte { return bytes.ReplaceAll(types, []byte{frPad}, nil) }

// pipeClient returns a client whose lanes are the near ends of net.Pipes, handed to the test on peers.
func pipeClient(t *testing.T) (*Client, chan net.Conn) {
	t.Helper()
	peers := make(chan net.Conn, 8)
	c, err := NewClient(ClientConfig{PSK: testPSK, Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		peers <- b
		return a, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, peers
}

// readHello reads one write from peer, checks the authentication header in front, and returns the
// frames that follow it in the same write.
func readHello(t *testing.T, c *Client, peer net.Conn) []byte {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 70000)
	n, err := peer.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	b = b[:n]
	if len(b) < authHead || !bytes.Equal(b[:32], c.token[:]) {
		t.Fatalf("the write does not start with the authentication header: %x", b[:minInt(len(b), 40)])
	}
	return b[authHead+int(binary.BigEndian.Uint16(b[32:])):]
}

// recConn keeps a copy of every Write.
type recConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recConn) first() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		return nil
	}
	return c.writes[0]
}

// ---- small records ----

func TestLengthSampler(t *testing.T) {
	for _, tc := range []struct {
		s     *lengthSampler
		table []smallLen
	}{{samplerUp, smallUp}, {samplerDown, smallDown}} {
		for _, min := range []int{0, 20, 26, 27, 100, 250, 299} {
			for i := 0; i < 500; i++ {
				if n := tc.s.pick(min); n != 0 && (n < min || !inTable(tc.table, n)) {
					t.Fatalf("picked %d for min %d", n, min)
				}
			}
		}
		if tc.s.pick(smallLimit) != 0 {
			t.Fatal("picked a length at or above the limit")
		}
	}
}

// A small record is padded in front to a length from the table; what it carries stays last.
func TestPadSmall(t *testing.T) {
	for _, server := range []bool{false, true} {
		table := smallUp
		if server {
			table = smallDown
		}
		l := &lane{server: server}
		end := []byte{frEnd, 0, 0}
		for i := 0; i < 200; i++ {
			out := l.padSmall(end)
			if n := len(out) + recordOverhead; !inTable(table, n) || !bytes.HasSuffix(out, end) {
				t.Fatalf("server=%v: END padded to a %d-byte record", server, n)
			}
			if !bytes.Equal(stripPad([][]byte{out}), end) {
				t.Fatalf("server=%v: frames changed", server)
			}
		}
		big := appendData(nil, make([]byte, smallLimit))
		if !bytes.Equal(l.padSmall(big), big) {
			t.Fatal("a record that is not small was padded")
		}
	}
}

// ---- schemes ----

// A lane's scheme comes from the PSK-derived family: deterministic for a nonce, different across nonces,
// within the generator's bounds; the PSK-derived scheme itself is untouched.
func TestLanePaddingScheme(t *testing.T) {
	token := sha256.Sum256([]byte("anon-test-psk-0123456789"))
	text, _ := derivedScheme(token)
	base := padding.NewPaddingFactory([]byte(text))
	a1, _ := laneScheme(token, []byte("nonce-a"))
	a2, _ := laneScheme(token, []byte("nonce-a"))
	if a1 != a2 {
		t.Fatal("the same nonce gave two schemes")
	}
	seen := map[string]bool{base.Md5: true}
	for i := 0; i < 200; i++ {
		p := newLaneScheme(token, base)
		if p == base {
			t.Fatal("no lane scheme drawn")
		}
		if p.Stop < 5 || p.Stop > 11 {
			t.Fatalf("stop %d", p.Stop)
		}
		if s := p.GenerateRecordPayloadSizes(0); len(s) != 1 || s[0] < 24 || s[0] > 64 {
			t.Fatalf("item 0 %v", s)
		}
		seen[p.Md5] = true
	}
	if len(seen) < 150 {
		t.Fatalf("only %d distinct schemes in 200 lanes", len(seen))
	}
	if again, _ := derivedScheme(token); again != text {
		t.Fatal("the PSK-derived scheme changed")
	}
}

// Lanes of one client shape with different schemes but announce the PSK-derived md5; a configured scheme
// is used as it is.
func TestClientLanesDrawTheirOwnScheme(t *testing.T) {
	c, _ := pipeClient(t)
	md5s := map[string]bool{}
	for i := 0; i < 4; i++ {
		l, err := c.dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if l.base != c.currentPadding() || !strings.Contains(string(l.prefix), "padding-md5="+l.base.Md5) {
			t.Fatal("the lane does not announce the client's base scheme")
		}
		md5s[l.scheme.Load().Md5] = true
	}
	if len(md5s) < 3 {
		t.Fatalf("4 lanes shaped with %d schemes", len(md5s))
	}
	const explicit = "stop=3\n0=40-40\n1=300-400"
	c2, err := NewClient(ClientConfig{PSK: testPSK, PaddingScheme: explicit,
		Dial: func(context.Context) (net.Conn, error) { a, _ := net.Pipe(); return a, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	l2, err := c2.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l2.scheme.Load() != l2.base || string(l2.base.RawScheme) != explicit {
		t.Fatal("configured scheme not used as is")
	}
}

// Only the lane's first packets are shaped, whichever stream they belong to.
func TestShapingCoversTheLaneStart(t *testing.T) {
	l, peer := pipeLane(t)
	l.scheme.Store(padding.NewPaddingFactory([]byte("stop=3\n0=30-30\n1=200-200\n2=300-300")))
	data := appendData(nil, []byte("x"))
	var lens []int
	for i := 0; i < 5; i++ {
		for _, x := range collect(t, l, peer, func() error { return l.writeLanePacket(data) }) {
			lens = append(lens, len(x))
		}
	}
	if want := []int{200, 300, len(data), len(data), len(data)}; fmt.Sprint(lens) != fmt.Sprint(want) {
		t.Fatalf("record lengths %v, want %v", lens, want)
	}
}

// The server compares the client's md5 with the lane's base: a client on the PSK-derived scheme gets no
// UpdatePaddingScheme. ServerSettings waits for settingsWait when nothing else is written.
func TestServerComparesWithBase(t *testing.T) {
	srv, err := NewServer(ServerConfig{Users: map[string]string{"u": testPSK}, Handler: relay})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := pskToken(testPSK)
	text, _ := derivedScheme(token)
	hello := append(append([]byte(nil), token[:]...), 0, 0)
	hello = appendFrame(hello, frSettings, []byte("v=2\nraw=0\npadding-md5="+padding.NewPaddingFactory([]byte(text)).Md5))
	a, b := net.Pipe()
	defer a.Close()
	rc := &recConn{Conn: b}
	go func() { _ = srv.Serve(context.Background(), rc) }()
	go func() { _, _ = a.Write(hello) }()
	_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := a.Read(make([]byte, 70000)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < settingsWait-100*time.Millisecond {
		t.Fatalf("ServerSettings after %v, before settingsWait", d)
	}
	if f := withoutPad(frameTypes(rc.first())); !bytes.Equal(f, []byte{frServerSettings}) {
		t.Fatalf("frames %v, want ServerSettings alone", f)
	}
}

// ---- lanes ----

// A lane writes nothing until its first use, which carries the header; an unused one waits in the pool
// no longer than the server's handshake timeout allows.
func TestUnusedLaneStaysSilent(t *testing.T) {
	c, peers := pipeClient(t)
	l, err := c.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-peers
	c.put(l, false)
	_ = peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("an unused lane wrote: %d %v", n, err)
	}
	if d := c.ttl(l, 0); d != l.preauthTTL || d < preauthLaneTTL*8/10 || d >= defaultHandshakeTimeout {
		t.Fatalf("an unused lane is kept %v", d)
	}
	got := make(chan []byte, 1)
	go func() { got <- readHello(t, c, peer) }()
	if err := l.writeUnshaped(appendData(nil, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if f := withoutPad(frameTypes(<-got)); !bytes.Equal(f, []byte{frSettings, frData}) {
		t.Fatalf("frames after the header: %v", f)
	}
	if l.unauthed.Load() {
		t.Fatal("still unauthenticated after the first write")
	}
}

// A stream's first write starts with the header and Settings: OPEN and the first payload in the same
// write; without payload the OPEN that follows firstPayloadWait carries them.
func TestColdLaneMergesHello(t *testing.T) {
	for _, withData := range []bool{true, false} {
		c, peers := pipeClient(t)
		conn, err := c.DialContext(context.Background(), M.ParseSocksaddr("example.com:80"))
		if err != nil {
			t.Fatal(err)
		}
		peer := <-peers
		if withData {
			go func() { _, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")) }()
		}
		want := []byte{frSettings, frOpen}
		if withData {
			want = append(want, frData)
		}
		if got := withoutPad(frameTypes(readHello(t, c, peer))); !bytes.HasPrefix(got, want) {
			t.Fatalf("data=%v: frames %v, want %v", withData, got, want)
		}
		go func() { _, _ = io.Copy(io.Discard, peer) }()
		conn.Close()
	}
}

// The first inner record of a raw segment rides in the announcing record when it fits.
func TestRawSegmentCarriesFirstRecord(t *testing.T) {
	rec := func(n int) []byte {
		return append([]byte{0x17, 3, 3, byte(n >> 8), byte(n)}, bytes.Repeat([]byte{byte(n)}, n)...)
	}
	for _, tc := range []struct {
		first int
		carry bool
	}{{120, true}, {4000, true}, {16380, false}, {16401, false}} {
		l, peer := pipeLane(t)
		a := rec(tc.first)
		b := append(rec(16401), rec(300)...)
		w := collect(t, l, peer, func() error { return l.writeRawRecords(a, b) })
		types := withoutPad(frameTypes(w[0]))
		rest := bytes.Join(w[1:], nil)
		if tc.carry {
			if !bytes.Equal(types, []byte{frData, frRaw}) || !bytes.Equal(rest, b) {
				t.Fatalf("first %d: frames %v", tc.first, types)
			}
		} else if !bytes.Equal(types, []byte{frRaw}) || !bytes.Equal(rest, append(append([]byte(nil), a...), b...)) {
			t.Fatalf("first %d: frames %v", tc.first, types)
		}
	}
}

// ---- probes ----

// A connection that is not a client goes to the fallback web server with the bytes already read: an
// HTTP request gets its answer, and so does a first record too short to be a header, at once.
func TestFallback(t *testing.T) {
	got := make(chan string, 8)
	back := listen(t, func(c net.Conn) {
		defer c.Close()
		var req []byte
		b := make([]byte, 4096)
		for {
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := c.Read(b)
			req = append(req, b[:n]...)
			if err != nil {
				break
			}
		}
		got <- string(req)
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	})
	addr := startServer(t, pairOptions{outer: "tls", server: ServerConfig{Fallback: back}})
	for _, what := range []string{"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "hello"} {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		_, _ = io.WriteString(c, what)
		resp, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasPrefix(string(resp), "HTTP/1.1 400") || time.Since(start) > 2*time.Second {
			t.Fatalf("probe %q: %q after %v", what, resp, time.Since(start))
		}
		if b := <-got; b != what {
			t.Fatalf("probe %q: the backend got %q", what, b)
		}
	}
	c := pair(t, pairOptions{outer: "tls", server: ServerConfig{Fallback: back}})
	roundTrip(t, c, echoTCP(t), random(1000), nil)
}

// ---- the wire ----

type capturedConn struct {
	mu       sync.Mutex
	up, down []byte
}

// captureRelay is a TCP relay to target that keeps a copy of both directions of every connection.
func captureRelay(t *testing.T, target string) (string, func() []*capturedConn) {
	var mu sync.Mutex
	var all []*capturedConn
	var wg sync.WaitGroup
	addr := listen(t, func(c net.Conn) {
		s, err := net.Dial("tcp", target)
		if err != nil {
			c.Close()
			return
		}
		cc := &capturedConn{}
		mu.Lock()
		all = append(all, cc)
		wg.Add(2)
		mu.Unlock()
		pump := func(dst, src net.Conn, up bool) {
			defer wg.Done()
			buf := make([]byte, 64<<10)
			for {
				n, err := src.Read(buf)
				if n > 0 {
					cc.mu.Lock()
					if up {
						cc.up = append(cc.up, buf[:n]...)
					} else {
						cc.down = append(cc.down, buf[:n]...)
					}
					cc.mu.Unlock()
					if _, werr := dst.Write(buf[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			_ = dst.(*net.TCPConn).CloseWrite()
		}
		go pump(s, c, true)
		go pump(c, s, false)
	})
	return addr, func() []*capturedConn {
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		return all
	}
}

// tlsRecordsParse reports where b stops reading as TLS records (-1: never) and how many bytes of an
// incomplete record are left at the end.
func tlsRecordsParse(b []byte) (desync, tail int) {
	pos := 0
	for pos+5 <= len(b) {
		typ, ver, n := b[pos], binary.BigEndian.Uint16(b[pos+1:]), int(binary.BigEndian.Uint16(b[pos+3:]))
		if typ < 20 || typ > 23 || !(ver == 0x0303 || pos == 0 && ver == 0x0301) || n > 16384+256 {
			return pos, 0
		}
		if pos+5+n > len(b) {
			break
		}
		pos += 5 + n
	}
	return -1, len(b) - pos
}

// splitConn cuts every write into pieces of random length and now and then pauses between two pieces for
// longer than a held record start may wait.
type splitConn struct {
	net.Conn
	mu  sync.Mutex
	rnd *mrand.Rand
}

func (c *splitConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		c.mu.Lock()
		k := 1 + c.rnd.Intn(20000)
		pause := c.rnd.Intn(40) == 0
		c.mu.Unlock()
		k = minInt(k, len(p))
		n, err := c.Conn.Write(p[:k])
		total += n
		if err != nil {
			return total, err
		}
		if p = p[k:]; pause && len(p) > 0 {
			time.Sleep(30 * time.Millisecond)
		}
	}
	return total, nil
}

// The bytes of a lane read as one sequence of TLS records in both directions, however the application
// and the destination cut their data, and whether or not a record's rest is late.
func TestWireReadsAsTLSRecords(t *testing.T) {
	events := collectEvents(t)
	addr := startServer(t, pairOptions{outer: "tls"})
	relayAddr, capture := captureRelay(t, addr)
	c, err := NewClient(ClientConfig{PSK: testPSK, Dial: outerDialer(relayAddr, "tls", nil)})
	if err != nil {
		t.Fatal(err)
	}
	cfg, wrap := innerTLS()
	var seed atomic.Int64
	target := listen(t, func(conn net.Conn) {
		defer conn.Close()
		tc := tls.Server(&splitConn{Conn: conn, rnd: mrand.New(mrand.NewSource(seed.Add(1)))}, cfg)
		var h [8]byte
		if _, err := io.ReadFull(tc, h[:]); err != nil {
			return
		}
		down, up := int(binary.BigEndian.Uint32(h[:4])), int64(binary.BigEndian.Uint32(h[4:]))
		sum := sha256.New()
		if _, err := io.CopyN(sum, tc, up); err != nil {
			return
		}
		_, _ = tc.Write(sum.Sum(nil))
		_, _ = tc.Write(bytes.Repeat([]byte{7}, down))
	})
	const down, up = 2 << 20, 1 << 20
	for i := 0; i < 2; i++ {
		conn := dial(t, c, target)
		tc := wrap(&splitConn{Conn: conn, rnd: mrand.New(mrand.NewSource(int64(100 + i)))})
		_ = tc.SetDeadline(time.Now().Add(30 * time.Second))
		var h [8]byte
		binary.BigEndian.PutUint32(h[:4], down)
		binary.BigEndian.PutUint32(h[4:], up)
		upload := random(up)
		if _, err := tc.Write(append(h[:], upload...)); err != nil {
			t.Fatal(err)
		}
		var sum [32]byte
		if _, err := io.ReadFull(tc, sum[:]); err != nil || sum != sha256.Sum256(upload) {
			t.Fatalf("upload damaged: %v", err)
		}
		got, err := io.ReadAll(io.LimitReader(tc, down))
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{7}, down)) {
			t.Fatalf("download damaged: %d bytes, %v", len(got), err)
		}
		tc.Close()
	}
	time.Sleep(100 * time.Millisecond)
	c.Close()
	for _, e := range []string{"client:raw", "server:raw"} {
		if events(e) == 0 {
			t.Errorf("%s never happened", e)
		}
	}
	for i, cc := range capture() {
		for _, d := range []struct {
			name string
			b    []byte
		}{{"up", cc.up}, {"down", cc.down}} {
			if at, tail := tlsRecordsParse(d.b); at >= 0 || tail != 0 {
				t.Errorf("conn %d %s (%d bytes): not TLS records at %d, %d bytes left over", i, d.name, len(d.b), at, tail)
			}
		}
	}
}
