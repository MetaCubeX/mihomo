package net

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func relayTCPPair(t *testing.T) (peer, relay *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	peer, err = net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	relay, err = l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	if err = peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return
}

func runTimeoutRelay(t *testing.T, left, right net.Conn, up, down time.Duration) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		RelayWithHalfCloseTimeout(left, right, up, down)
		close(done)
	}()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
		waitRelayDone(t, done)
	})
	return done
}

func waitRelayDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not join its copy goroutines")
	}
}

func relayStillOpen(t *testing.T, done <-chan struct{}, duration time.Duration) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("relay closed while it should remain usable")
	case <-time.After(duration):
	}
}

func sendRelayBytes(t *testing.T, src, dst net.Conn, payload []byte) {
	t.Helper()
	if _, err := src.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(dst, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("relay changed payload")
	}
}

func TestRelayHalfCloseIdleCleanup(t *testing.T) {
	for _, uploadEOF := range []bool{false, true} {
		name := "upstream_fin_client_keeps_socket"
		if uploadEOF {
			name = "client_fin_upstream_keeps_socket"
		}
		t.Run(name, func(t *testing.T) {
			client, left := relayTCPPair(t)
			server, right := relayTCPPair(t)
			up, down := 3*time.Second, 100*time.Millisecond
			if uploadEOF {
				up, down = down, up
			}
			done := runTimeoutRelay(t, left, right, up, down)
			ending, receiving := server, client
			if uploadEOF {
				ending, receiving = client, server
			}
			if err := ending.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if data, err := io.ReadAll(receiving); err != nil || len(data) != 0 {
				t.Fatalf("EOF was not propagated: data=%q err=%v", data, err)
			}
			// The peer deliberately keeps its other direction open, as in the
			// Foxmail incident. Cleanup must complete without the peer exiting.
			waitRelayDone(t, done)
		})
	}
}

func TestRelayHalfCloseProgressRefreshesIdle(t *testing.T) {
	for _, uploadEOF := range []bool{false, true} {
		name := "remaining_upload"
		if uploadEOF {
			name = "remaining_download"
		}
		t.Run(name, func(t *testing.T) {
			client, left := relayTCPPair(t)
			server, right := relayTCPPair(t)
			const timeout = 300 * time.Millisecond
			done := runTimeoutRelay(t, left, right, timeout, timeout)
			ending, receiving := server, client
			if uploadEOF {
				ending, receiving = client, server
			}
			if err := ending.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(receiving); err != nil {
				t.Fatal(err)
			}
			// Forward for several idle allowances; an absolute drain timer would
			// truncate this valid one-way transfer.
			for i := 0; i < 10; i++ {
				relayStillOpen(t, done, timeout/4)
				sendRelayBytes(t, receiving, ending, []byte("progress"))
			}
			waitRelayDone(t, done)
		})
	}
}

func TestRelayFullyOpenHasNoIdleTimeout(t *testing.T) {
	client, left := relayTCPPair(t)
	server, right := relayTCPPair(t)
	done := runTimeoutRelay(t, left, right, 50*time.Millisecond, 50*time.Millisecond)
	relayStillOpen(t, done, 200*time.Millisecond)
	sendRelayBytes(t, client, server, []byte("request"))
	sendRelayBytes(t, server, client, []byte("response"))
	_ = client.CloseWrite()
	_ = server.CloseWrite()
	waitRelayDone(t, done)
}

func TestRelayHalfCloseTimeoutCanBeDisabled(t *testing.T) {
	client, left := relayTCPPair(t)
	server, right := relayTCPPair(t)
	done := runTimeoutRelay(t, left, right, time.Second, 0)
	_ = server.CloseWrite()
	if _, err := io.ReadAll(client); err != nil {
		t.Fatal(err)
	}
	relayStillOpen(t, done, 150*time.Millisecond)
	sendRelayBytes(t, client, server, []byte("still open"))
	_ = client.CloseWrite()
	waitRelayDone(t, done)
}

func TestRelayHalfClosePreservesBufferedDataAndCounters(t *testing.T) {
	client, left := relayTCPPair(t)
	server, right := relayTCPPair(t)
	payload := bytes.Repeat([]byte("buffered payload"), 1024)
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffered := NewBufferedConn(left)
	if _, err := buffered.Peek(4); err != nil {
		t.Fatal(err)
	}
	counted := &relayCountingConn{Conn: right}
	done := runTimeoutRelay(t, buffered, counted, time.Second, time.Second)
	_ = client.CloseWrite()
	got, err := io.ReadAll(server)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("buffered transfer: bytes=%d err=%v", len(got), err)
	}
	_ = server.CloseWrite()
	waitRelayDone(t, done)
	if counted.written != int64(len(payload)) {
		t.Fatalf("traffic counter=%d, want %d", counted.written, len(payload))
	}
}

type relayCountingConn struct {
	net.Conn
	written int64
}

func (c *relayCountingConn) UnwrapWriter() (io.Writer, []CountFunc) {
	return c.Conn, []CountFunc{func(n int64) { c.written += n }}
}

func (c *relayCountingConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

type relayCloseWriteFailure struct{ net.Conn }

func (*relayCloseWriteFailure) CloseWrite() error { return errors.New("injected CloseWrite failure") }

func TestRelayHalfCloseFailureClosesBothDirections(t *testing.T) {
	client, left := relayTCPPair(t)
	server, right := relayTCPPair(t)
	done := runTimeoutRelay(t, &relayCloseWriteFailure{left}, right, 0, 0)
	_ = server.CloseWrite()
	waitRelayDone(t, done)
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client remained open after CloseWrite failure")
	}
}

type relayBlockedWriter struct {
	net.Conn
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *relayBlockedWriter) Write([]byte) (int, error) {
	close(c.entered)
	<-c.closed
	return 0, net.ErrClosed
}

func (c *relayBlockedWriter) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *relayBlockedWriter) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

func TestRelayHalfCloseTimeoutInterruptsBlockedWrite(t *testing.T) {
	client, left := relayTCPPair(t)
	server, right := relayTCPPair(t)
	blocked := &relayBlockedWriter{Conn: left, entered: make(chan struct{}), closed: make(chan struct{})}
	done := runTimeoutRelay(t, blocked, right, 100*time.Millisecond, time.Second)
	if _, err := server.Write([]byte("blocked response")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("copy did not enter Write")
	}
	_ = client.CloseWrite()
	waitRelayDone(t, done)
}

func TestRelayHalfCloseRepeatedSessionsReleaseCopies(t *testing.T) {
	var sessions []<-chan struct{}
	for i := 0; i < 64; i++ {
		client, left := relayTCPPair(t)
		server, right := relayTCPPair(t)
		done := runTimeoutRelay(t, left, right, time.Second, 100*time.Millisecond)
		_ = server.CloseWrite()
		if _, err := io.ReadAll(client); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, done)
	}
	for _, done := range sessions {
		waitRelayDone(t, done)
	}
}
