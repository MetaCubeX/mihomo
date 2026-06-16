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

func TestPoolConnCloseIsIdempotent(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return nil, errors.New("factory should not be called")
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if _, err := conn.Write([]byte{Version, CommandConnectV2, 0}); err != nil {
		t.Fatal(err)
	}
	conn.MarkReusable()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if rawConn.writes != 2 {
		t.Fatalf("close should send the request and one half-close record, got %d writes", rawConn.writes)
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got != pooledConn {
		t.Fatal("pooled connection mismatch")
	}
}

func TestPoolConnCloseBeforeRequestClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if rawConn.writes != 0 {
		t.Fatalf("close before request should not send half-close record, got %d writes", rawConn.writes)
	}
	if !rawConn.closed {
		t.Fatal("close before request should close the raw connection")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got != factoryConn {
		t.Fatal("unstarted connection should not be returned to the pool")
	}
}

func TestPoolConnCloseAfterRequestBeforeReusableClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if _, err := conn.Write([]byte{Version, CommandConnectV2, 0}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if rawConn.writes != 1 {
		t.Fatalf("close before reusable should only send the request, got %d writes", rawConn.writes)
	}
	if !rawConn.closed {
		t.Fatal("close before reusable should close the raw connection")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got != factoryConn {
		t.Fatal("connection closed before reusable should not be returned to the pool")
	}
}

func TestPoolConnCloseWriteBeforeRequestClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if rawConn.writes != 0 {
		t.Fatalf("CloseWrite before request should not send half-close record, got %d writes", rawConn.writes)
	}
	if !rawConn.closed {
		t.Fatal("CloseWrite before request should close the raw connection")
	}

	// MarkReusable must not revive a connection that already took the raw-close path.
	conn.MarkReusable()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got != factoryConn {
		t.Fatal("unstarted connection should not be returned to the pool")
	}
}

func TestPoolConnCloseWriteDoesNotReturnConnectionToPool(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn, reply: true}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if _, err := conn.Write([]byte{Version, CommandConnectV2, 0}); err != nil {
		t.Fatal(err)
	}
	conn.MarkReusable()
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got != factoryConn {
		t.Fatal("CloseWrite should not put the active connection back into the pool")
	}
	if rawConn.writes != 2 {
		t.Fatalf("CloseWrite should send the request and one half-close record, got %d writes", rawConn.writes)
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
	if got != pooledConn {
		t.Fatal("Close should return the connection to the pool after CloseWrite")
	}
	if rawConn.writes != 2 {
		t.Fatalf("Close after CloseWrite should not send another half-close record, got %d writes", rawConn.writes)
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
