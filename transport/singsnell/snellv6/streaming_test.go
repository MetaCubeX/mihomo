package snellv6_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/mihomo/transport/singsnell/snellv6"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/stretchr/testify/require"
)

// streamingEchoHandler echoes bytes as they arrive, like a real relay would.
type streamingEchoHandler struct{}

func (streamingEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose snell.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		_ = N.CloseWrite(conn)
		_ = conn.Close()
		onClose(err)
	}()
}

func (streamingEchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose snell.CloseHandlerFunc) {
	echoHandler{}.NewPacketConnectionEx(ctx, conn, source, destination, onClose)
}

func startStreamingServer(t *testing.T, mode snellv6.Mode) string {
	t.Helper()
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(testPSK), Mode: mode, Handler: streamingEchoHandler{}})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				if err := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), func(error) {}); err != nil {
					conn.Close()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// streamingRoundTrip writes while concurrently reading, without half-closing
// first, which is how a proxy relay drives the connection.
func streamingRoundTrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	go func() { _, _ = conn.Write(payload) }()
	received := make([]byte, len(payload))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err := io.ReadFull(conn, received)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, received), "payload mismatch")
}

func TestStreamingReuse(t *testing.T) {
	for name, mode := range testModes {
		t.Run(name, func(t *testing.T) {
			address := startStreamingServer(t, mode)
			client, err := snellv6.NewClient(snellv6.ClientOptions{
				PSK: []byte(testPSK), Mode: mode, Reuse: true,
				Dialer: N.SystemDialer, Server: M.ParseSocksaddr(address),
			})
			require.NoError(t, err)
			defer client.Close()
			for round := 0; round < 2; round++ {
				conn, err := client.DialContext(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
				require.NoError(t, err)
				streamingRoundTrip(t, conn, randomPayload(t, 16*1024))
				require.NoError(t, conn.Close())
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

func TestStreamingNoReuse(t *testing.T) {
	for name, mode := range testModes {
		t.Run(name, func(t *testing.T) {
			address := startStreamingServer(t, mode)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Mode: mode})
			require.NoError(t, err)
			serverConn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			defer serverConn.Close()
			conn, err := client.DialConn(serverConn, M.ParseSocksaddrHostPort("example.com", 443))
			require.NoError(t, err)
			streamingRoundTrip(t, conn, randomPayload(t, 16*1024))
		})
	}
}
