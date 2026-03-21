package net_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"

	"github.com/stretchr/testify/assert"
)

func testRead(ctx context.Context, conn net.Conn) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}
	_, err = conn.Read(make([]byte, 1))
	return err
}

func TestSetupContextForConnWithCancel(t *testing.T) {
	t.Parallel()
	c1, c2 := N.Pipe()
	defer c1.Close()
	defer c2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error)
	go func() {
		errc <- testRead(ctx, c1)
	}()

	select {
	case <-errc:
		t.Fatal("conn closed before cancel")
	case <-time.After(100 * time.Millisecond):
		cancel()
	}

	select {
	case err := <-errc:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("conn not be canceled")
	}
}

func TestSetupContextForConnWithTimeout1(t *testing.T) {
	t.Parallel()
	c1, c2 := N.Pipe()
	defer c1.Close()
	defer c2.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errc := make(chan error)
	go func() {
		errc <- testRead(ctx, c1)
	}()

	select {
	case err := <-errc:
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal("conn closed before timeout")
		}
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("conn not be canceled")
	}
}

func TestSetupContextForConnWithTimeout2(t *testing.T) {
	t.Parallel()
	c1, c2 := N.Pipe()
	defer c1.Close()
	defer c2.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	errc := make(chan error)
	go func() {
		errc <- testRead(ctx, c1)
	}()

	select {
	case <-errc:
		t.Fatal("conn closed before cancel")
	case <-time.After(100 * time.Millisecond):
		c2.Write(make([]byte, 1))
	}

	select {
	case err := <-errc:
		assert.Nil(t, ctx.Err())
		assert.Nil(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("conn not be canceled")
	}
}
