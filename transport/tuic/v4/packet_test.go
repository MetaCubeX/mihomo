package v4

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/transport/tuic/types"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func testQUICPair(t *testing.T) (*quic.Conn, *quic.Conn) {
	t.Helper()
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	require.NoError(t, err)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"tuic-test"}}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"tuic-test"}}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.CloseWithError(0, "done") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.CloseWithError(0, "done") })
	return client, server
}

type signaledReadConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *signaledReadConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

func TestPacketConnConcurrentClose(t *testing.T) {
	client, server := testQUICPair(t)
	left, right := net.Pipe()
	defer right.Close()
	defer left.Close()
	var callbacks atomic.Int32
	input := &signaledReadConn{Conn: left, started: make(chan struct{})}
	conn := &quicStreamPacketConn{connId: 7, quicConn: client, inputConn: N.NewBufferedConn(input), maxUdpRelayPacketSize: 1200, udpRelayMode: types.NATIVE, closeDeferFn: func() { callbacks.Add(1) }}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 1)
	wg.Add(4)
	go func() { defer wg.Done(); _, _, _ = conn.ReadFrom(make([]byte, 128)) }()
	select {
	case <-input.started:
	case <-time.After(5 * time.Second):
		t.Fatal("packet read did not block on the input stream")
	}
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
		for i := 0; i < 100; i++ {
			_, _ = conn.WriteTo([]byte("packet"), address)
		}
	}()
	go func() { defer wg.Done(); <-start; results <- conn.Close() }()
	close(start)
	wg.Wait()
	require.NoError(t, <-results)
	require.NoError(t, conn.Close())
	require.EqualValues(t, 1, callbacks.Load())
	_, _, err := conn.ReadFrom(make([]byte, 128))
	require.ErrorIs(t, err, net.ErrClosed)
	_, _, _, err = conn.WaitReadFrom()
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = conn.WriteTo([]byte("packet"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	require.ErrorIs(t, err, net.ErrClosed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := server.AcceptUniStream(ctx)
	require.NoError(t, err)
	got, err := io.ReadAll(stream)
	require.NoError(t, err)
	var want bytes.Buffer
	require.NoError(t, NewDissociate(7).WriteTo(&want))
	require.Equal(t, want.Bytes(), got)
}

func TestPacketConnConcurrentReaders(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	require.NoError(t, left.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, right.SetDeadline(time.Now().Add(5*time.Second)))
	conn := &quicStreamPacketConn{inputConn: N.NewBufferedConn(left)}
	const count = 64
	var encoded bytes.Buffer
	address := NewAddressAddrPort(netip.MustParseAddrPort("127.0.0.1:53"))
	for i := 0; i < count; i++ {
		payload := []byte{byte(i), 0x41, 0x42, 0x43}
		packet := NewPacket(7, uint16(len(payload)), address, payload)
		require.NoError(t, packet.WriteTo(&encoded))
	}
	sent := make(chan error, 1)
	go func() { _, err := right.Write(encoded.Bytes()); sent <- err }()
	received := make(chan []byte, count)
	results := make(chan error, 2)
	for _, wait := range []bool{false, true} {
		wait := wait
		go func() {
			for i := 0; i < count/2; i++ {
				var data []byte
				var err error
				if wait {
					var put func()
					data, put, _, err = conn.WaitReadFrom()
					data = bytes.Clone(data)
					if put != nil {
						put()
					}
				} else {
					data = make([]byte, 16)
					var n int
					n, _, err = conn.ReadFrom(data)
					data = data[:n]
				}
				if err != nil {
					results <- err
					return
				}
				received <- data
			}
			results <- nil
		}()
	}
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	require.NoError(t, <-sent)
	close(received)
	seen := make(map[byte]bool)
	for data := range received {
		require.Len(t, data, 4)
		require.Equal(t, []byte{0x41, 0x42, 0x43}, data[1:])
		require.False(t, seen[data[0]], "duplicate packet")
		seen[data[0]] = true
	}
	require.Len(t, seen, count)
}
