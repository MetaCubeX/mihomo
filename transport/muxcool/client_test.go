package muxcool

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServer is a minimal Mux.Cool server echoing everything back.
type testServer struct {
	destinations sync.Map
	// closeAfterData makes the server answer "bye" and end the sub connection on its first data
	closeAfterData bool
}

func (h *testServer) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	networks := map[uint16]byte{}
	for {
		var header [2]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return
		}
		meta := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(reader, meta); err != nil {
			return
		}
		id, status, option := binary.BigEndian.Uint16(meta), meta[2], meta[3]
		switch status {
		case statusNew:
			networks[id] = meta[4]
			port := binary.BigEndian.Uint16(meta[5:])
			var destination M.Socksaddr
			switch meta[7] {
			case addrTypeDomain:
				destination = M.ParseSocksaddrHostPort(string(meta[9:9+int(meta[8])]), port)
			default:
				addr, _ := netip.AddrFromSlice(meta[8:])
				destination = M.SocksaddrFrom(addr, port)
			}
			h.destinations.Store(destination.String(), true)
		case statusEnd:
			delete(networks, id)
		}
		if option&optionData == 0 {
			continue
		}
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return
		}
		data := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(reader, data); err != nil {
			return
		}
		if _, ok := networks[id]; !ok {
			continue
		}
		if h.closeAfterData {
			data = []byte("bye")
		}
		frame := []byte{0, 4, byte(id >> 8), byte(id), statusKeep, optionData, byte(len(data) >> 8), byte(len(data))}
		frame = append(frame, data...)
		if h.closeAfterData {
			delete(networks, id)
			frame = append(frame, 0, 4, byte(id>>8), byte(id), statusEnd, 0)
		}
		if _, err := conn.Write(frame); err != nil {
			return
		}
	}
}

func newTestClient(t *testing.T, concurrency int) (*Client, *testServer, *atomic.Int32) {
	handler := &testServer{}
	dials := &atomic.Int32{}
	client := NewClient(func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		clientConn, serverConn := net.Pipe()
		go handler.serve(serverConn)
		return clientConn, nil
	}, concurrency)
	t.Cleanup(func() { _ = client.Close() })
	return client, handler, dials
}

func echo(t *testing.T, conn net.Conn, size int) {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i)
	}
	go func() {
		_, err := conn.Write(data)
		assert.NoError(t, err)
	}()
	got := make([]byte, size)
	_, err := io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, data, got)
}

func TestClientMultiplex(t *testing.T) {
	client, handler, dials := newTestClient(t, 4)

	destinations := []M.Socksaddr{
		M.ParseSocksaddrHostPort("example.com", 443),
		M.ParseSocksaddrHostPort("1.2.3.4", 80),
		M.ParseSocksaddrHostPort("2001:db8::1", 8443),
	}
	var conns []net.Conn
	for i := 0; i < 8; i++ {
		conn, err := client.DialContext(context.Background(), destinations[i%len(destinations)])
		require.NoError(t, err)
		conns = append(conns, conn)
	}
	// 8 sub connections with a concurrency of 4 need exactly 2 connections
	assert.EqualValues(t, 2, dials.Load())

	var wg sync.WaitGroup
	for _, conn := range conns {
		conn := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			echo(t, conn, 100*1024) // bigger than one frame
		}()
	}
	wg.Wait()

	for _, destination := range destinations {
		_, ok := handler.destinations.Load(destination.String())
		assert.True(t, ok, "server didn't see %s", destination)
	}

	// closed sub connections free their slot
	for _, conn := range conns[:4] {
		require.NoError(t, conn.Close())
	}
	for i := 0; i < 4; i++ {
		conn, err := client.DialContext(context.Background(), destinations[0])
		require.NoError(t, err)
		echo(t, conn, 1024)
	}
	assert.EqualValues(t, 2, dials.Load())
}

func TestClientRemoteClose(t *testing.T) {
	client, handler, dials := newTestClient(t, 0)
	handler.closeAfterData = true

	for i := 0; i < 3; i++ {
		conn, err := client.DialContext(context.Background(), M.ParseSocksaddrHostPort("example.com", 80))
		require.NoError(t, err)
		_, err = conn.Write([]byte("hello"))
		require.NoError(t, err)
		data, err := io.ReadAll(conn)
		require.NoError(t, err) // a clean End frame is an EOF
		assert.Equal(t, "bye", string(data))
		require.NoError(t, conn.Close())
	}
	assert.EqualValues(t, 1, dials.Load())
}

func TestClientConnectionBroken(t *testing.T) {
	var serverConns []net.Conn
	var access sync.Mutex
	handler := &testServer{}
	client := NewClient(func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		access.Lock()
		serverConns = append(serverConns, serverConn)
		access.Unlock()
		go handler.serve(serverConn)
		return clientConn, nil
	}, 0)
	defer client.Close()

	conn, err := client.DialContext(context.Background(), M.ParseSocksaddrHostPort("example.com", 80))
	require.NoError(t, err)
	echo(t, conn, 1024)

	access.Lock()
	_ = serverConns[0].Close()
	access.Unlock()

	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)

	// a new connection is transparently opened
	conn, err = client.DialContext(context.Background(), M.ParseSocksaddrHostPort("example.com", 80))
	require.NoError(t, err)
	echo(t, conn, 1024)
	access.Lock()
	assert.Len(t, serverConns, 2)
	access.Unlock()

	require.NoError(t, client.Close())
	_, err = client.DialContext(context.Background(), M.ParseSocksaddrHostPort("example.com", 80))
	assert.ErrorIs(t, err, ErrClientClosed)
	_, err = conn.Read(make([]byte, 1))
	assert.Error(t, err)
}

func TestStreamDeadline(t *testing.T) {
	client, _, _ := newTestClient(t, 0)
	conn, err := client.DialContext(context.Background(), M.ParseSocksaddrHostPort("example.com", 80))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	start := time.Now()
	_, err = conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second)

	// the conn is still usable after the deadline is reset
	require.NoError(t, conn.SetDeadline(time.Time{}))
	echo(t, conn, 1024)

	require.NoError(t, conn.SetDeadline(time.Now().Add(-time.Second)))
	_, err = conn.Write([]byte("x"))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	_, err = conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
}
