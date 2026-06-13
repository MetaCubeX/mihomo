package snell

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

// defaultMaxUsesPerConn caps how many CONNECT sessions a single reuse-mode
// TCP connection may serve before we close it instead of returning to the
// pool. Surge's snell-server (v5.0.1 observed) closes a reuse-mode TCP
// after the second session, so anything beyond the cap is a soon-to-be
// dead socket from the client's perspective.
const defaultMaxUsesPerConn = 2

// drainReuseTimeout bounds how long PoolConn.Close waits for the server's
// zero-chunk half-close before declaring the conn unreusable. The server
// emits its zero chunk shortly after seeing ours, so one RTT plus slack is
// plenty; if the upstream is still streaming data we'd rather drop the
// conn than block the caller.
const drainReuseTimeout = 500 * time.Millisecond

type Pool struct {
	pool           *pool.Pool[*pooledEntry]
	maxUsesPerConn int
}

// pooledEntry is the internal pool element. It tracks how many CONNECT
// sessions the wrapped TCP has served so far so the pool can evict it
// before the server-side use cap kicks in.
type pooledEntry struct {
	conn *Snell
	uses int
}

func (p *Pool) Get() (net.Conn, error) {
	return p.GetContext(context.Background())
}

func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	entry, err := p.pool.GetContext(ctx)
	if err != nil {
		return nil, err
	}
	entry.uses++
	return &PoolConn{Snell: entry.conn, pool: p, uses: entry.uses}, nil
}

func (p *Pool) put(conn *Snell, uses int) {
	if p.maxUsesPerConn > 0 && uses >= p.maxUsesPerConn {
		_ = conn.Close()
		return
	}
	p.pool.Put(&pooledEntry{conn: conn, uses: uses})
}

type PoolConn struct {
	*Snell
	pool           *Pool
	uses           int
	closeWriteOnce sync.Once
	closeWriteErr  error
	closeOnce      sync.Once
	closeErr       error
}

func (pc *PoolConn) Read(b []byte) (int, error) {
	n, err := pc.Snell.Read(b)
	if err == shadowaead.ErrZeroChunk {
		return n, io.EOF
	}
	return n, err
}

func (pc *PoolConn) Write(b []byte) (int, error) {
	return pc.Snell.Write(b)
}

func (pc *PoolConn) CloseWrite() error {
	pc.closeWriteOnce.Do(func() {
		pc.closeWriteErr = writeZeroChunk(pc.Snell)
	})
	return pc.closeWriteErr
}

func (pc *PoolConn) Close() error {
	pc.closeOnce.Do(func() {
		if err := pc.CloseWrite(); err != nil {
			pc.closeErr = err
			_ = pc.Snell.Close()
			return
		}

		// If the relay terminated because the local side closed first (typical
		// for short HTTP/1 responses), the server may still have data queued
		// in the TCP receive buffer — most importantly its own zero-chunk
		// half-close. Reusing this conn without draining would surface that
		// stale data on the next session's first read. Drain until we see the
		// server's zero chunk or hit drainReuseTimeout; only then put back.
		if !pc.drainPendingForReuse() {
			_ = pc.Snell.Close()
			return
		}

		// mihomo uses SetReadDeadline to break bidirectional copy between
		// client and server; reset it before reuse to avoid io timeout error.
		_ = pc.Snell.Conn.SetReadDeadline(time.Time{})
		pc.Snell.reply = false
		pc.pool.put(pc.Snell, pc.uses)
	})
	return pc.closeErr
}

// drainPendingForReuse reads remaining frames from the snell stream until
// the server's zero-chunk half-close is observed, with a short deadline.
// Returns true if the conn is in a clean state suitable for pool reuse.
func (pc *PoolConn) drainPendingForReuse() bool {
	if err := pc.Snell.Conn.SetReadDeadline(time.Now().Add(drainReuseTimeout)); err != nil {
		return false
	}
	scratch := make([]byte, 4096)
	for {
		_, err := pc.Snell.Read(scratch)
		if errors.Is(err, shadowaead.ErrZeroChunk) {
			return true
		}
		if err != nil {
			return false
		}
	}
}

func NewPool(factory func(context.Context) (*Snell, error)) *Pool {
	p := &Pool{maxUsesPerConn: defaultMaxUsesPerConn}
	p.pool = pool.New[*pooledEntry](
		func(ctx context.Context) (*pooledEntry, error) {
			c, err := factory(ctx)
			if err != nil {
				return nil, err
			}
			return &pooledEntry{conn: c}, nil
		},
		pool.WithAge[*pooledEntry](15000),
		pool.WithSize[*pooledEntry](10),
		pool.WithEvict[*pooledEntry](func(item *pooledEntry) {
			_ = item.conn.Close()
		}),
	)

	return p
}
