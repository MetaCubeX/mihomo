package snell

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

func TestPoolConnCloseDrainsAndReturnsToPool(t *testing.T) {
	rawConn := &drainConn{}
	pooledConn := &Snell{Conn: rawConn, reply: true}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return nil, errors.New("factory should not be called")
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool, uses: 1}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if rawConn.writes != 1 {
		t.Fatalf("close should send one half-close record, got %d", rawConn.writes)
	}
	if !rawConn.readDeadlineCleared {
		t.Fatal("close should clear read deadline before returning to pool")
	}
	if rawConn.closed {
		t.Fatal("close should not close the underlying conn when drain succeeds")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != pooledConn {
		t.Fatal("pooled connection mismatch")
	}
	if got.uses != 1 {
		t.Fatalf("uses count not preserved: got %d, want 1", got.uses)
	}
}

func TestPoolConnCloseDiscardsWhenDrainFails(t *testing.T) {
	rawConn := &recordingConn{} // Read returns io.EOF, not ErrZeroChunk
	pooledConn := &Snell{Conn: rawConn, reply: true}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool, uses: 1}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !rawConn.closed {
		t.Fatal("close should close the underlying conn when drain fails")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("drained-failed conn should not be returned to the pool")
	}
}

func TestPoolConnCloseDiscardsAtMaxUsesPerConn(t *testing.T) {
	rawConn := &drainConn{}
	pooledConn := &Snell{Conn: rawConn, reply: true}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	// uses == defaultMaxUsesPerConn — this Close must not return to the pool.
	conn := &PoolConn{Snell: pooledConn, pool: pool, uses: defaultMaxUsesPerConn}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !rawConn.closed {
		t.Fatal("close should close the underlying conn at the per-conn use cap")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("capped conn should not be returned to the pool")
	}
}

func TestPoolGetContextIncrementsUses(t *testing.T) {
	factoryCalls := 0
	factoryConn := &Snell{Conn: &drainConn{}, reply: true}
	pool := NewPool(func(context.Context) (*Snell, error) {
		factoryCalls++
		return factoryConn, nil
	})

	first, err := pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	pcFirst := first.(*PoolConn)
	if pcFirst.uses != 1 {
		t.Fatalf("first checkout uses: got %d, want 1", pcFirst.uses)
	}
	if err := pcFirst.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	pcSecond := second.(*PoolConn)
	if pcSecond.uses != 2 {
		t.Fatalf("second checkout uses: got %d, want 2", pcSecond.uses)
	}
	if pcSecond.Snell != factoryConn {
		t.Fatal("second checkout should reuse the same TCP conn")
	}
	if factoryCalls != 1 {
		t.Fatalf("factory should be called once across both checkouts, got %d", factoryCalls)
	}
}

func TestPoolConnCloseWriteDoesNotReturnConnectionToPool(t *testing.T) {
	rawConn := &drainConn{}
	pooledConn := &Snell{Conn: rawConn, reply: true}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool, uses: 1}

	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("CloseWrite should not put the active connection back into the pool")
	}
	if rawConn.writes != 1 {
		t.Fatalf("CloseWrite should send one half-close record, got %d", rawConn.writes)
	}
	if !pooledConn.reply {
		t.Fatal("CloseWrite should not reset reply while the read side may still be active")
	}

	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	got, err = pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != pooledConn {
		t.Fatal("Close should return the connection to the pool after CloseWrite")
	}
	if rawConn.writes != 1 {
		t.Fatalf("Close after CloseWrite should not send another half-close record, got %d", rawConn.writes)
	}
	if pooledConn.reply {
		t.Fatal("Close should reset reply before returning the connection to the pool")
	}
}

func TestPoolConnReadZeroChunkReturnsEOF(t *testing.T) {
	conn := &PoolConn{Snell: &Snell{Conn: zeroChunkConn{}, reply: true}}

	n, err := conn.Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("read length mismatch: %d", n)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF for zero chunk, got %v", err)
	}
}

type recordingConn struct {
	writes int
	closed bool
}

func (c *recordingConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

func (c *recordingConn) Close() error {
	c.closed = true
	return nil
}

func (*recordingConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (*recordingConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (*recordingConn) SetDeadline(time.Time) error {
	return nil
}

func (*recordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*recordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

type recordingAddr string

func (a recordingAddr) Network() string {
	return string(a)
}

func (a recordingAddr) String() string {
	return string(a)
}

// drainConn lets Close drain to completion: Read immediately surfaces the
// server's zero-chunk half-close, and SetReadDeadline records whether the
// caller cleared the drain deadline on the way out.
type drainConn struct {
	writes              int
	closed              bool
	readDeadlineCleared bool
}

func (c *drainConn) Read([]byte) (int, error) {
	return 0, shadowaead.ErrZeroChunk
}

func (c *drainConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

func (c *drainConn) Close() error {
	c.closed = true
	return nil
}

func (*drainConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (*drainConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (*drainConn) SetDeadline(time.Time) error {
	return nil
}

func (c *drainConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadlineCleared = true
	}
	return nil
}

func (*drainConn) SetWriteDeadline(time.Time) error {
	return nil
}

type zeroChunkConn struct{}

func (zeroChunkConn) Read([]byte) (int, error) {
	return 0, shadowaead.ErrZeroChunk
}

func (zeroChunkConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (zeroChunkConn) Close() error {
	return nil
}

func (zeroChunkConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (zeroChunkConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (zeroChunkConn) SetDeadline(time.Time) error {
	return nil
}

func (zeroChunkConn) SetReadDeadline(time.Time) error {
	return nil
}

func (zeroChunkConn) SetWriteDeadline(time.Time) error {
	return nil
}
