package sudoku

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func TestUserHash_StableAcrossTableRotation(t *testing.T) {
	tables := []*sudokuobfs.Table{
		sudokuobfs.NewTable("seed-a", "prefer_ascii"),
		sudokuobfs.NewTable("seed-b", "prefer_ascii"),
	}
	key := "userhash-stability-key"
	target := "example.com:80"

	serverCfg := DefaultConfig()
	serverCfg.Key = key
	serverCfg.AEADMethod = "chacha20-poly1305"
	serverCfg.Tables = tables
	serverCfg.PaddingMin = 0
	serverCfg.PaddingMax = 0
	serverCfg.EnablePureDownlink = true
	serverCfg.HandshakeTimeoutSeconds = 5
	serverCfg.DisableHTTPMask = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	const attempts = 32
	hashCh := make(chan string, attempts)
	errCh := make(chan error, attempts)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				session, err := ServerHandshake(conn, serverCfg)
				if err != nil {
					errCh <- err
					return
				}
				defer session.Conn.Close()
				hashCh <- session.UserHash
			}(c)
		}
	}()

	clientCfg := DefaultConfig()
	*clientCfg = *serverCfg
	clientCfg.ServerAddress = ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for i := 0; i < attempts; i++ {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", clientCfg.ServerAddress)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		cConn, err := ClientHandshake(raw, clientCfg)
		if err != nil {
			_ = raw.Close()
			t.Fatalf("handshake %d: %v", i, err)
		}

		addrBuf, err := EncodeAddress(target)
		if err != nil {
			_ = cConn.Close()
			t.Fatalf("encode addr %d: %v", i, err)
		}
		if _, err := cConn.Write(addrBuf); err != nil {
			_ = cConn.Close()
			t.Fatalf("write addr %d: %v", i, err)
		}
		_ = cConn.Close()
	}

	unique := map[string]struct{}{}
	deadline := time.After(10 * time.Second)
	for i := 0; i < attempts; i++ {
		select {
		case err := <-errCh:
			t.Fatalf("server handshake error: %v", err)
		case h := <-hashCh:
			if h == "" {
				t.Fatalf("empty user hash")
			}
			if len(h) != 16 {
				t.Fatalf("unexpected user hash length: %d", len(h))
			}
			unique[h] = struct{}{}
		case <-deadline:
			t.Fatalf("timeout waiting for server handshakes")
		}
	}
	if len(unique) != 1 {
		t.Fatalf("user hash should be stable across table rotation; got %d distinct values", len(unique))
	}
}

func TestMultiplex_TCP_Echo(t *testing.T) {
	table := sudokuobfs.NewTable("seed", "prefer_ascii")
	key := "test-key-mux"
	target := "example.com:80"

	serverCfg := DefaultConfig()
	serverCfg.Key = key
	serverCfg.AEADMethod = "chacha20-poly1305"
	serverCfg.Table = table
	serverCfg.PaddingMin = 0
	serverCfg.PaddingMax = 0
	serverCfg.EnablePureDownlink = true
	serverCfg.HandshakeTimeoutSeconds = 5
	serverCfg.DisableHTTPMask = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var handshakes int64
	var streams int64
	done := make(chan struct{})

	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()

		session, err := ServerHandshake(raw, serverCfg)
		if err != nil {
			return
		}
		atomic.AddInt64(&handshakes, 1)

		if session.Type != SessionTypeMultiplex {
			_ = session.Conn.Close()
			return
		}

		mux, err := AcceptMultiplexServer(session.Conn)
		if err != nil {
			return
		}
		defer mux.Close()

		for {
			stream, dst, err := mux.AcceptTCP()
			if err != nil {
				return
			}
			if dst != target {
				_ = stream.Close()
				return
			}
			atomic.AddInt64(&streams, 1)
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(stream)
		}
	}()

	clientCfg := DefaultConfig()
	*clientCfg = *serverCfg
	clientCfg.ServerAddress = ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", clientCfg.ServerAddress)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	cConn, err := ClientHandshake(raw, clientCfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	mux, err := StartMultiplexClient(cConn)
	if err != nil {
		_ = cConn.Close()
		t.Fatalf("start mux: %v", err)
	}
	defer mux.Close()

	for i := 0; i < 6; i++ {
		s, err := mux.Dial(ctx, target)
		if err != nil {
			t.Fatalf("dial stream %d: %v", i, err)
		}

		msg := []byte("hello-mux")
		if _, err := s.Write(msg); err != nil {
			_ = s.Close()
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(s, buf); err != nil {
			_ = s.Close()
			t.Fatalf("read: %v", err)
		}
		_ = s.Close()
		if !bytes.Equal(buf, msg) {
			t.Fatalf("echo mismatch: got %q", buf)
		}
	}

	_ = mux.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("server did not exit")
	}

	if got := atomic.LoadInt64(&handshakes); got != 1 {
		t.Fatalf("unexpected handshake count: %d", got)
	}
	if got := atomic.LoadInt64(&streams); got < 6 {
		t.Fatalf("unexpected stream count: %d", got)
	}
}

func TestMultiplex_Boundary_InvalidVersion(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })

	errCh := make(chan error, 1)
	go func() {
		_, err := AcceptMultiplexServer(server)
		errCh <- err
	}()

	// AcceptMultiplexServer expects the magic byte to have been consumed already; write a bad version byte.
	_, _ = client.Write([]byte{0xFF})
	if err := <-errCh; err == nil {
		t.Fatalf("expected error")
	}
}
