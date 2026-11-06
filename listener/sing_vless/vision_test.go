package sing_vless

import (
	"io"
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestVisionResponseHeadroomConcurrent(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	require.NoError(t, left.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, right.SetDeadline(time.Now().Add(5*time.Second)))
	response := &serverConn{ExtendedConn: N.NewExtendedConn(left)}
	conn, err := vision.NewConn(response, encryption.NewCommonConn(left, false), uuid.Nil)
	require.NoError(t, err)
	defer conn.Close()
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("response"))
		written <- err
	}()
	// Buffer allocation can inspect the wrapper chain while the first response
	// is being written. Keep that write pending until observation has finished.
	for i := 0; i < 1000; i++ {
		N.CalculateFrontHeadroom(conn)
	}
	drained := make(chan struct{})
	go func() { defer close(drained); _, _ = io.Copy(io.Discard, right) }()
	select {
	case err := <-written:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("response write did not complete")
	}
	require.NoError(t, conn.Close())
	<-drained
}
