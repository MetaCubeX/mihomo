package snell

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

type Pool struct {
	pool *pool.Pool[*Snell]
}

const (
	poolConnNew int32 = iota
	poolConnReusable
	poolConnClosed
)

func (p *Pool) Get() (net.Conn, error) {
	return p.GetContext(context.Background())
}

func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	elm, err := p.pool.GetContext(ctx)
	if err != nil {
		return nil, err
	}

	return &PoolConn{Snell: elm, pool: p}, nil
}

func (p *Pool) Put(conn *Snell) {
	if err := HalfClose(conn); err != nil {
		_ = conn.Close()
		return
	}

	p.put(conn)
}

func (p *Pool) put(conn *Snell) {
	p.pool.Put(conn)
}

type PoolConn struct {
	*Snell
	pool               *Pool
	closeWriteOnce     sync.Once
	closeWriteReusable bool
	closeWriteErr      error
	closeOnce          sync.Once
	closeErr           error
	reusableState      atomic.Int32
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

// MarkReusable allows Close to return this request to the pool after the request header is committed.
func (pc *PoolConn) MarkReusable() {
	pc.reusableState.CompareAndSwap(poolConnNew, poolConnReusable)
}

func (pc *PoolConn) CloseWrite() error {
	_, err := pc.closeWrite()
	return err
}

func (pc *PoolConn) closeWrite() (bool, error) {
	pc.closeWriteOnce.Do(func() {
		if pc.reusableState.Swap(poolConnClosed) != poolConnReusable {
			pc.closeWriteErr = pc.Snell.Close()
			return
		}
		pc.closeWriteReusable = true
		pc.closeWriteErr = writeZeroChunk(pc.Snell)
	})
	return pc.closeWriteReusable, pc.closeWriteErr
}

func (pc *PoolConn) Close() error {
	pc.closeOnce.Do(func() {
		reusable, err := pc.closeWrite()
		if err != nil {
			pc.closeErr = err
			_ = pc.Snell.Close()
			return
		}
		if !reusable {
			return
		}

		// mihomo use SetReadDeadline to break bidirectional copy between client and server.
		// reset it before reuse connection to avoid io timeout error.
		_ = pc.Snell.Conn.SetReadDeadline(time.Time{})
		pc.Snell.reply = false
		pc.pool.put(pc.Snell)
	})
	return pc.closeErr
}

func NewPool(factory func(context.Context) (*Snell, error)) *Pool {
	p := pool.New[*Snell](
		func(ctx context.Context) (*Snell, error) {
			return factory(ctx)
		},
		pool.WithAge[*Snell](15000),
		pool.WithSize[*Snell](10),
		pool.WithEvict[*Snell](func(item *Snell) {
			_ = item.Close()
		}),
	)

	return &Pool{pool: p}
}
