package snell

import (
	"context"
	"net"
	"time"

	"github.com/metacubex/mihomo/component/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

type Pool struct {
	pool *pool.Pool[*Snell]
}

func (p *Pool) Get() (net.Conn, error) {
	return p.GetContext(context.Background())
}

func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	elm, err := p.pool.GetContext(ctx)
	if err != nil {
		return nil, err
	}

	return &PoolConn{elm, p}, nil
}

func (p *Pool) Put(conn *Snell) {
	if err := HalfClose(conn); err != nil {
		_ = conn.Close()
		return
	}

	p.pool.Put(conn)
}

type PoolConn struct {
	*Snell
	pool *Pool
}

func (pc *PoolConn) Read(b []byte) (int, error) {
	// save old status of reply (it mutable by Read)
	reply := pc.Snell.reply

	n, err := pc.Snell.Read(b)
	if err == shadowaead.ErrZeroChunk {
		// if reply is false, it should be client halfclose.
		// ignore error and read data again.
		if !reply {
			pc.Snell.reply = false
			return pc.Snell.Read(b)
		}
	}
	return n, err
}

func (pc *PoolConn) Write(b []byte) (int, error) {
	return pc.Snell.Write(b)
}

func (pc *PoolConn) Close() error {
	// mihomo use SetReadDeadline to break bidirectional copy between client and server.
	// reset it before reuse connection to avoid io timeout error.
	_ = pc.Snell.Conn.SetReadDeadline(time.Time{})
	pc.pool.Put(pc.Snell)
	return nil
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
