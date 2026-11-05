package snell

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"

	"github.com/stretchr/testify/require"
)

var v6TestModes = map[string]V6Mode{
	"default":    V6ModeDefault,
	"unshaped":   V6ModeUnshaped,
	"unsafe-raw": V6ModeUnsafeRaw,
}

const v6TestPSK = "snell-v6-test-psk-0123456789"

func TestV6ParseMode(t *testing.T) {
	for _, name := range []string{"", "default", "unshaped", "unsafe-raw"} {
		_, err := ParseV6Mode(name)
		require.NoError(t, err, name)
	}
	_, err := ParseV6Mode("bogus")
	require.Error(t, err)
	require.Equal(t, "unshaped", V6ModeUnshaped.String())
}

func TestV6ProfileDeterministic(t *testing.T) {
	a := newV6Profile([]byte(v6TestPSK))
	b := newV6Profile([]byte(v6TestPSK))
	require.True(t, reflect.DeepEqual(a, b), "same psk must derive the same profile")

	c := newV6Profile([]byte(v6TestPSK + "x"))
	require.False(t, reflect.DeepEqual(a.namespaces, c.namespaces), "different psk must derive a different profile")
}

func TestV6SaltBlockRoundTrip(t *testing.T) {
	for i := 0; i < 32; i++ {
		psk := make([]byte, 24)
		_, err := rand.Read(psk)
		require.NoError(t, err)
		profile := newV6Profile(psk)

		salt, err := v6RandomSalt()
		require.NoError(t, err)
		block := make([]byte, profile.saltBlockLen)
		profile.fillPadding(0xffffffff, block)
		profile.writeSaltBlock(salt, block)
		extracted := profile.extractSalt(block)
		require.Equal(t, salt, extracted[:])
	}
}

func TestV6MixRoundTrip(t *testing.T) {
	for i := 0; i < 32; i++ {
		psk := make([]byte, 16)
		_, err := rand.Read(psk)
		require.NoError(t, err)
		profile := newV6Profile(psk)

		padding := make([]byte, 300)
		payload := make([]byte, 700)
		_, _ = rand.Read(padding)
		_, _ = rand.Read(payload)
		origPadding := append([]byte(nil), padding...)
		origPayload := append([]byte(nil), payload...)

		profile.mixPaddingPayload(uint32(i), padding, payload)
		profile.mixPaddingPayload(uint32(i), padding, payload)
		require.Equal(t, origPadding, padding)
		require.Equal(t, origPayload, payload)
	}
}

// v6Pair returns a client and a server side wrapped with the v6 record layer
// over a real loopback TCP connection.
func v6Pair(t *testing.T, mode V6Mode) (client, server *Snell) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	serverConn, ok := <-accepted
	require.True(t, ok)
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	return StreamConnV6(clientConn, []byte(v6TestPSK), mode), ServerStreamConnV6(serverConn, []byte(v6TestPSK), mode)
}

func TestV6ConnStream(t *testing.T) {
	for name, mode := range v6TestModes {
		t.Run(name, func(t *testing.T) {
			client, server := v6Pair(t, mode)
			payload := make([]byte, 300*1024)
			_, err := rand.Read(payload)
			require.NoError(t, err)

			errCh := make(chan error, 1)
			go func() {
				_, err := client.Write(payload)
				if err == nil {
					err = HalfClose(client)
				}
				errCh <- err
			}()

			received := make([]byte, len(payload))
			require.NoError(t, server.SetReadDeadline(time.Now().Add(10*time.Second)))
			_, err = io.ReadFull(server.Conn, received)
			require.NoError(t, err)
			require.True(t, bytes.Equal(payload, received), "payload mismatch")
			require.NoError(t, <-errCh)

			// the zero chunk ends the stream
			_, err = server.Conn.Read(received[:1])
			require.True(t, errors.Is(err, shadowaead.ErrZeroChunk), "expected zero chunk, got %v", err)

			// and the other direction works independently
			reply := []byte("hello from server")
			_, err = server.Write(reply)
			require.NoError(t, err)
			got := make([]byte, len(reply))
			require.NoError(t, client.SetReadDeadline(time.Now().Add(10*time.Second)))
			_, err = io.ReadFull(client.Conn, got)
			require.NoError(t, err)
			require.Equal(t, reply, got)
		})
	}
}

func TestV6ConnPacketFrames(t *testing.T) {
	for name, mode := range v6TestModes {
		t.Run(name, func(t *testing.T) {
			client, server := v6Pair(t, mode)
			for round := 0; round < 20; round++ {
				// sizes above the shaped chunk limit must still arrive as one record
				packet := make([]byte, 1400+round*97)
				_, err := rand.Read(packet)
				require.NoError(t, err)
				_, err = client.WritePacketFrame(packet)
				require.NoError(t, err)

				buf := make([]byte, 64*1024)
				require.NoError(t, server.SetReadDeadline(time.Now().Add(10*time.Second)))
				n, err := server.Conn.Read(buf)
				require.NoError(t, err)
				require.Equal(t, len(packet), n, "a packet frame must be read back in one piece")
				require.True(t, bytes.Equal(packet, buf[:n]))
			}
		})
	}
}

func TestV6ConnWrongPSK(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		server := ServerStreamConnV6(conn, []byte(v6TestPSK+"-other"), V6ModeDefault)
		buf := make([]byte, 16)
		_, _ = server.Conn.Read(buf)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	client := StreamConnV6(conn, []byte(v6TestPSK), V6ModeDefault)
	_, err = client.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = client.Conn.Read(make([]byte, 16))
	require.Error(t, err, "the server must not produce a readable reply with a different psk")
}

func TestValidateV6PSK(t *testing.T) {
	require.Error(t, ValidateV6PSK([]byte("short")))
	require.Error(t, ValidateV6PSK(make([]byte, 256)))
	require.NoError(t, ValidateV6PSK([]byte(v6TestPSK)))
}
