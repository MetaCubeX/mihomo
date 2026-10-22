package nat

import (
	"errors"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func sourceTestSession(t *testing.T, table *Table, source, origin string, config C.UDPConfig) (C.UDPSessionKey, C.PacketSender, C.NatSource) {
	t.Helper()
	var key C.UDPSessionKey
	sender, group, loaded := table.GetOrCreateSession(source, M.ParseSocksaddr(origin), config, func(created C.UDPSessionKey, _ C.NatSource, _ C.UDPConfig) C.PacketSender {
		key = created
		return &tableTestSender{}
	})
	require.False(t, loaded)
	return key, sender, group
}

func sourceTestConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestSourceGroupCreationError(t *testing.T) {
	table := New()
	key, sender, source := sourceTestSession(t, table, "source", "192.0.2.1:443", C.UDPConfig{})
	wantErr := errors.New("socket creation failed")
	for i := 0; i < 2; i++ {
		_, err := source.WithLocalConn("192.0.2.1:443", func() (*net.UDPConn, error) {
			return nil, wantErr
		}, func(*net.UDPConn) (int, error) {
			t.Fatal("a failed creation must not write")
			return 0, nil
		})
		require.ErrorIs(t, err, wantErr)
	}
	require.True(t, table.DeleteSession(key, sender))
}

func TestSourceGroupCloseDuringCreationAndWrite(t *testing.T) {
	table := New()
	key, sender, source := sourceTestSession(t, table, "source", "192.0.2.1:443", C.UDPConfig{})
	group := source.(*sourceGroup)
	conn := sourceTestConn(t)
	creating := make(chan struct{})
	created := make(chan struct{})
	writing := make(chan struct{})
	written := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		_, err := source.WithLocalConn("192.0.2.1:443", func() (*net.UDPConn, error) {
			close(creating)
			<-created
			return conn, nil
		}, func(conn *net.UDPConn) (int, error) {
			close(writing)
			<-written
			return 0, conn.SetReadDeadline(time.Time{})
		})
		writeDone <- err
	}()
	<-creating
	closed := make(chan bool, 1)
	go func() { closed <- table.DeleteSession(key, sender) }()
	require.Eventually(t, func() bool {
		group.mu.Lock()
		defer group.mu.Unlock()
		return group.closing
	}, time.Second, time.Millisecond)
	_, _, loaded := table.LoadSession("source", M.ParseSocksaddr("192.0.2.1:443"))
	require.False(t, loaded, "a closing group must stop publishing its session before local writes finish")

	// An empty intermediate generation must not let its successor bypass the
	// still-active original sockets when it closes before opening any itself.
	middleKey, middleSender, middle := sourceTestSession(t, table, "source", "192.0.2.1:443", C.UDPConfig{})
	middleClosed := make(chan bool, 1)
	go func() { middleClosed <- table.DeleteSession(middleKey, middleSender) }()
	require.Eventually(t, func() bool {
		g := middle.(*sourceGroup)
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.closing
	}, time.Second, time.Millisecond)
	replacementSender := &tableTestSender{}
	_, replacement, _ := table.GetOrCreateSession("source", M.ParseSocksaddr("192.0.2.1:443"), C.UDPConfig{}, func(C.UDPSessionKey, C.NatSource, C.UDPConfig) C.PacketSender {
		return replacementSender
	})
	replacementStarted := make(chan struct{})
	replacementReady := make(chan error, 1)
	address := conn.LocalAddr().(*net.UDPAddr)
	go func() {
		close(replacementStarted)
		_, err := replacement.WithLocalConn("192.0.2.1:443", func() (*net.UDPConn, error) {
			return net.ListenUDP("udp", address)
		}, func(local *net.UDPConn) (int, error) { return 0, local.SetReadDeadline(time.Time{}) })
		replacementReady <- err
	}()
	<-replacementStarted
	require.Eventually(t, func() bool {
		g := replacement.(*sourceGroup)
		g.mu.Lock()
		defer g.mu.Unlock()
		return len(g.local) != 0
	}, time.Second, time.Millisecond)
	close(created)
	<-writing
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	select {
	case <-closed:
		t.Fatal("source closed while a reply was still writing")
	case <-replacementReady:
		t.Fatal("replacement socket created before old local sockets closed")
	case <-time.After(20 * time.Millisecond):
	}
	close(written)
	require.NoError(t, <-writeDone)
	require.True(t, <-closed)
	require.True(t, <-middleClosed)
	require.NoError(t, <-replacementReady)
	require.NotSame(t, source, replacement)
	require.ErrorIs(t, conn.SetReadDeadline(time.Time{}), net.ErrClosed)
	_, err := source.WithLocalConn("192.0.2.1:443", func() (*net.UDPConn, error) {
		t.Fatal("old source must never open a replacement socket")
		return nil, nil
	}, func(*net.UDPConn) (int, error) { return 0, nil })
	require.ErrorIs(t, err, net.ErrClosed)
	require.False(t, table.DeleteSession(key, sender))
	current, currentGroup, loaded := table.LoadSession("source", M.ParseSocksaddr("192.0.2.1:443"))
	require.True(t, loaded)
	require.Same(t, replacementSender, current)
	require.Same(t, replacement, currentGroup)
	require.True(t, table.DeleteSession(key, replacementSender))
}
