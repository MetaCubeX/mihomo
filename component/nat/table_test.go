package nat

import (
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type tableTestSender struct {
	C.PacketSender
}

func TestTableDeleteSessionRetainsReplacement(t *testing.T) {
	table := New()
	const sourceKey = "127.0.0.1:10000"
	key, old, _ := sourceTestSession(t, table, sourceKey, "192.0.2.1:443", C.UDPConfig{})
	replacement := &tableTestSender{}
	require.True(t, table.DeleteSession(key, old))
	_, source, _ := table.GetOrCreateSession(sourceKey, M.Socksaddr{}, C.UDPConfig{}, func(C.UDPSessionKey, C.NatSource, C.UDPConfig) C.PacketSender {
		return replacement
	})

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = source.WithLocalConn("192.0.2.1:443", func() (*net.UDPConn, error) {
		return conn, nil
	}, func(*net.UDPConn) (int, error) { return 0, nil })
	require.NoError(t, err)

	// A delayed cleanup from the old session must leave the replacement's
	// entry and its local socket alive, even though the source key is reused.
	require.False(t, table.DeleteSession(key, old))
	sender, currentSource, loaded := table.GetOrCreateSession(sourceKey, M.Socksaddr{}, C.UDPConfig{}, func(C.UDPSessionKey, C.NatSource, C.UDPConfig) C.PacketSender {
		t.Fatal("the replacement must remain registered")
		return nil
	})
	require.True(t, loaded)
	require.Same(t, replacement, sender)
	require.Same(t, source, currentSource)
	_, err = source.WithLocalConn("192.0.2.1:443", func() (*net.UDPConn, error) {
		t.Fatal("the replacement's local socket must remain registered")
		return nil, nil
	}, func(local *net.UDPConn) (int, error) {
		require.Same(t, conn, local)
		return 0, nil
	})
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))

	require.True(t, table.DeleteSession(key, replacement))
	_, loaded = table.mapping.Load(sourceKey)
	require.False(t, loaded)
	require.ErrorIs(t, conn.SetReadDeadline(time.Time{}), net.ErrClosed)
	require.False(t, table.DeleteSession(key, replacement))
}
