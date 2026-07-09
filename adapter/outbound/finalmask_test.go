package outbound

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

// rangeOf is a small test helper for building utils.Range[int].
func rangeOf(start, end int) utils.Range[int] {
	return utils.NewRange(start, end)
}

// recordConn captures each Write as a separate byte slice. Used by tests in
// this package to inspect how a chain of layers actually chopped up the data.
type recordConn struct {
	writes [][]byte
	closed bool
}

func newRecordConn() *recordConn { return &recordConn{} }

func (r *recordConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (r *recordConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	r.writes = append(r.writes, cp)
	return len(p), nil
}
func (r *recordConn) Close() error                     { r.closed = true; return nil }
func (r *recordConn) LocalAddr() net.Addr              { return nil }
func (r *recordConn) RemoteAddr() net.Addr             { return nil }
func (r *recordConn) SetDeadline(time.Time) error      { return nil }
func (r *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (r *recordConn) SetWriteDeadline(time.Time) error { return nil }

func (r *recordConn) total() []byte {
	var out []byte
	for _, w := range r.writes {
		out = append(out, w...)
	}
	return out
}

func TestFinalMaskOption_Parse(t *testing.T) {
	t.Run("nil receiver returns nil", func(t *testing.T) {
		var opt *FinalMaskOption
		if opt.Parse() != nil {
			t.Fatal("expected nil")
		}
	})

	t.Run("empty returns nil", func(t *testing.T) {
		if (&FinalMaskOption{}).Parse() != nil {
			t.Fatal("expected nil")
		}
	})

	t.Run("UDP-only returns nil (warned)", func(t *testing.T) {
		opt := &FinalMaskOption{
			UDP: []FinalMaskLayer{{Type: "noise"}},
		}
		if opt.Parse() != nil {
			t.Fatal("expected nil since UDP is not implemented")
		}
	})

	t.Run("QUICParams-only returns nil (warned)", func(t *testing.T) {
		opt := &FinalMaskOption{QUICParams: map[string]any{"congestion": "bbr"}}
		if opt.Parse() != nil {
			t.Fatal("expected nil since quicParams is not implemented")
		}
	})

	t.Run("single valid TCP layer", func(t *testing.T) {
		opt := &FinalMaskOption{
			TCP: []FinalMaskLayer{
				{Type: "fragment", Settings: FinalMaskLayerSettings{Packets: "tlshello", Lengths: []string{"10-20"}}},
			},
		}
		cfg := opt.Parse()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if len(cfg.tcpLayers) != 1 {
			t.Fatalf("got %d layers, want 1", len(cfg.tcpLayers))
		}
	})

	t.Run("unknown layer type is skipped", func(t *testing.T) {
		opt := &FinalMaskOption{
			TCP: []FinalMaskLayer{
				{Type: "fragment", Settings: FinalMaskLayerSettings{Packets: "tlshello", Lengths: []string{"10-20"}}},
				{Type: "nonexistent"},
			},
		}
		cfg := opt.Parse()
		if cfg == nil || len(cfg.tcpLayers) != 1 {
			t.Fatalf("expected exactly 1 surviving layer, got %v", cfg)
		}
	})

	t.Run("invalid fragment config skips layer", func(t *testing.T) {
		opt := &FinalMaskOption{
			TCP: []FinalMaskLayer{
				// Last length entry is 0 — must be rejected.
				{Type: "fragment", Settings: FinalMaskLayerSettings{Lengths: []string{"10", "0"}}},
			},
		}
		cfg := opt.Parse()
		if cfg != nil {
			t.Fatalf("expected nil when all layers invalid, got %v", cfg)
		}
	})
}

// TestFinalMask_ChainWrapOrder verifies that layers[0] is the innermost layer
// (closest to the real conn) per the FinalMask spec. Each test layer injects
// a fixed byte slice once, before the first downstream Write only.
func TestFinalMask_ChainWrapOrder(t *testing.T) {
	cfg := &finalMaskConfig{
		tcpLayers: []finalMaskLayer{
			&prefixOnceLayer{prefix: []byte("INNER:")}, // layers[0] = innermost
			&prefixOnceLayer{prefix: []byte("OUTER:")}, // layers[1] = outermost
		},
	}

	rc := newRecordConn()
	var conn net.Conn = rc
	for _, l := range cfg.tcpLayers {
		conn = l.wrap(conn)
	}

	if _, err := conn.Write([]byte("DATA")); err != nil {
		t.Fatal(err)
	}

	// INNER wraps real_conn directly, so its prefix is the FIRST bytes seen
	// on the wire. OUTER wraps INNER, so when OUTER's prefix is forwarded
	// through INNER, INNER has already injected its own. Result stream:
	//   INNER: OUTER: DATA
	got := string(rc.total())
	want := "INNER:OUTER:DATA"
	if got != want {
		t.Errorf("wire bytes = %q, want %q", got, want)
	}
}

// prefixOnceLayer is a test-only finalMaskLayer whose conn prepends a fixed
// byte slice to the first Write that flows through it.
type prefixOnceLayer struct{ prefix []byte }

func (p *prefixOnceLayer) wrap(conn net.Conn) net.Conn {
	return &prefixOnceConn{Conn: conn, p: p}
}

type prefixOnceConn struct {
	net.Conn
	p    *prefixOnceLayer
	done bool
}

func (c *prefixOnceConn) Write(data []byte) (int, error) {
	if !c.done {
		c.done = true
		if _, err := c.Conn.Write(c.p.prefix); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(data)
}
