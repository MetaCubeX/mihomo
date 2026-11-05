package snellv6_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/mihomo/transport/singsnell/snellv6"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/stretchr/testify/require"
)

const testPSK = "snell-v6-loopback-psk-0123456789"

var testModes = map[string]snellv6.Mode{
	"default":    snellv6.ModeDefault,
	"unshaped":   snellv6.ModeUnshaped,
	"unsafe-raw": snellv6.ModeUnsafeRaw,
}

// echoHandler echoes TCP streams and UDP datagrams straight back to the client.
type echoHandler struct{}

func (echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose snell.CloseHandlerFunc) {
	go func() {
		var err error
		defer func() {
			_ = N.CloseWrite(conn)
			_ = conn.Close()
			onClose(err)
		}()
		// mirror a real upstream: consume the request until the client half-closes,
		// then send the response back
		var payload []byte
		payload, err = io.ReadAll(conn)
		if err != nil {
			return
		}
		_, err = conn.Write(payload)
	}()
}

func (echoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose snell.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		readWaitOptions := N.NewReadWaitOptions(conn, conn)
		for {
			buffer := readWaitOptions.NewPacketBuffer()
			dest, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			if err = conn.WritePacket(buffer, dest); err != nil {
				return
			}
		}
	}()
}

type testServer struct {
	address string
	accepts atomic.Int32
}

func startServer(t *testing.T, mode snellv6.Mode) *testServer {
	t.Helper()
	service, err := snellv6.NewService(snellv6.ServerOptions{
		PSK:     []byte(testPSK),
		Mode:    mode,
		Handler: echoHandler{},
	})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	server := &testServer{address: listener.Addr().String()}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.accepts.Add(1)
			go func() {
				err := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), func(error) {})
				if err != nil {
					conn.Close()
				}
			}()
		}
	}()
	return server
}

func randomPayload(t *testing.T, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	return payload
}

func echoRoundTrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	_, err := conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, N.CloseWrite(conn))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, received), "payload mismatch")
}

func TestLoopbackTCP(t *testing.T) {
	for name, mode := range testModes {
		t.Run(name, func(t *testing.T) {
			server := startServer(t, mode)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Mode: mode})
			require.NoError(t, err)

			serverConn, err := net.Dial("tcp", server.address)
			require.NoError(t, err)
			defer serverConn.Close()

			proxyConn, err := client.DialConn(serverConn, M.ParseSocksaddrHostPort("example.com", 443))
			require.NoError(t, err)
			echoRoundTrip(t, proxyConn, randomPayload(t, 256*1024))
		})
	}
}

func TestLoopbackTCPEarlyData(t *testing.T) {
	for name, mode := range testModes {
		t.Run(name, func(t *testing.T) {
			server := startServer(t, mode)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Mode: mode})
			require.NoError(t, err)

			serverConn, err := net.Dial("tcp", server.address)
			require.NoError(t, err)
			defer serverConn.Close()

			proxyConn := client.DialEarlyConn(serverConn, M.ParseSocksaddrHostPort("127.0.0.1", 80))
			require.True(t, proxyConn.(N.EarlyConn).NeedHandshake())
			// larger than one record so the request and payload span several frames
			echoRoundTrip(t, proxyConn, randomPayload(t, 80*1024))
			require.False(t, proxyConn.(N.EarlyConn).NeedHandshake())
		})
	}
}

func TestLoopbackUDP(t *testing.T) {
	for name, mode := range testModes {
		t.Run(name, func(t *testing.T) {
			server := startServer(t, mode)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Mode: mode})
			require.NoError(t, err)

			serverConn, err := net.Dial("tcp", server.address)
			require.NoError(t, err)
			defer serverConn.Close()

			packetConn, err := client.DialPacketConn(serverConn)
			require.NoError(t, err)
			target := M.ParseSocksaddrHostPort("127.0.0.1", 53).UDPAddr()

			for round := 0; round < 10; round++ {
				message := randomPayload(t, 1400)
				_, err = packetConn.WriteTo(message, target)
				require.NoError(t, err)

				received := make([]byte, 2048)
				require.NoError(t, packetConn.SetReadDeadline(time.Now().Add(10*time.Second)))
				n, from, err := packetConn.ReadFrom(received)
				require.NoError(t, err)
				require.Equal(t, target.String(), from.String())
				require.True(t, bytes.Equal(message, received[:n]), "round %d", round)
			}
		})
	}
}

func TestLoopbackReuse(t *testing.T) {
	for name, mode := range testModes {
		t.Run(name, func(t *testing.T) {
			server := startServer(t, mode)
			client, err := snellv6.NewClient(snellv6.ClientOptions{
				PSK:    []byte(testPSK),
				Mode:   mode,
				Reuse:  true,
				Dialer: N.SystemDialer,
				Server: M.ParseSocksaddr(server.address),
			})
			require.NoError(t, err)
			defer client.Close()

			destination := M.ParseSocksaddrHostPort("example.com", 443)
			for round := 0; round < 3; round++ {
				conn, err := client.DialContext(context.Background(), destination)
				require.NoError(t, err)
				echoRoundTrip(t, conn, randomPayload(t, 16*1024))
				require.NoError(t, conn.Close())
				// give the session time to return to the pool before the next dial
				time.Sleep(50 * time.Millisecond)
			}
			require.Equal(t, int32(1), server.accepts.Load(), "sessions should be reused over a single tcp connection")
		})
	}
}

func TestClientOptionsValidation(t *testing.T) {
	_, err := snellv6.NewClient(snellv6.ClientOptions{})
	require.ErrorIs(t, err, snell.ErrMissingPSK)

	_, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Mode: snellv6.Mode(99)})
	require.Error(t, err)

	_, err = snellv6.NewService(snellv6.ServerOptions{PSK: []byte("short")})
	require.Error(t, err)

	for _, name := range []string{"", "default", "unshaped", "unsafe-raw"} {
		_, err = snellv6.ParseMode(name)
		require.NoError(t, err, name)
	}
	_, err = snellv6.ParseMode("bogus")
	require.Error(t, err)
}
