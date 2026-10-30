package tunnel

import (
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForLateSniffClientData(t *testing.T) {
	t.Run("client data arrives first", func(t *testing.T) {
		clientApp, clientTunnel := net.Pipe()
		remoteTunnel, remoteServer := net.Pipe()
		t.Cleanup(func() {
			_ = clientApp.Close()
			_ = clientTunnel.Close()
			_ = remoteTunnel.Close()
			_ = remoteServer.Close()
		})

		go func() {
			_, _ = clientApp.Write([]byte("client hello"))
		}()

		clientConn := N.NewBufferedConn(clientTunnel)
		remoteConn := N.NewBufferedConn(remoteTunnel)
		assert.True(t, waitForLateSniffClientData(clientConn, remoteConn))
		data, err := clientConn.Peek(len("client hello"))
		require.NoError(t, err)
		assert.Equal(t, "client hello", string(data))
		assert.Zero(t, remoteConn.Buffered())
	})

	t.Run("server greeting arrives first", func(t *testing.T) {
		clientApp, clientTunnel := net.Pipe()
		remoteTunnel, remoteServer := net.Pipe()
		t.Cleanup(func() {
			_ = clientApp.Close()
			_ = clientTunnel.Close()
			_ = remoteTunnel.Close()
			_ = remoteServer.Close()
		})

		go func() {
			_, _ = remoteServer.Write([]byte("server greeting"))
		}()

		clientConn := N.NewBufferedConn(clientTunnel)
		remoteConn := N.NewBufferedConn(remoteTunnel)
		assert.False(t, waitForLateSniffClientData(clientConn, remoteConn))
		data, err := remoteConn.Peek(len("server greeting"))
		require.NoError(t, err)
		assert.Equal(t, "server greeting", string(data))
		assert.Zero(t, clientConn.Buffered())
	})

	t.Run("server data after client win is detected before reroute", func(t *testing.T) {
		clientApp, clientTunnel := net.Pipe()
		remoteTunnel, remoteServer := net.Pipe()
		t.Cleanup(func() {
			_ = clientApp.Close()
			_ = clientTunnel.Close()
			_ = remoteTunnel.Close()
			_ = remoteServer.Close()
		})

		go func() {
			_, _ = clientApp.Write([]byte("client"))
		}()

		clientConn := N.NewBufferedConn(clientTunnel)
		remoteConn := N.NewBufferedConn(remoteTunnel)
		assert.True(t, waitForLateSniffClientData(clientConn, remoteConn))

		require.True(t, remoteConn.AppendData([]byte("server")))
		assert.True(t, hasPendingData(remoteConn))
	})
}

func TestHasPendingData(t *testing.T) {
	app, tunnel := net.Pipe()
	t.Cleanup(func() {
		_ = app.Close()
		_ = tunnel.Close()
	})

	conn := N.NewBufferedConn(tunnel)
	assert.False(t, hasPendingData(conn))

	go func() {
		_, _ = app.Write([]byte("x"))
	}()
	deadline := time.Now().Add(time.Second)
	_ = conn.SetReadDeadline(deadline)
	_, err := conn.Peek(1)
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Time{})
	assert.True(t, hasPendingData(conn))
}
