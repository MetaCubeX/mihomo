//go:build linux

package fragment

import (
	"context"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOOB(t *testing.T) {
	steps, err := ParseOOB("")
	require.NoError(t, err)
	assert.Empty(t, steps)

	steps, err = ParseOOB("0, _,255")
	require.NoError(t, err)
	assert.Equal(t, []OOBStep{{Byte: 0}, {Passthrough: true}, {Byte: 255}}, steps)

	for _, bad := range []string{"256", "-1", "a", "0,,1", ","} {
		_, err = ParseOOB(bad)
		assert.Error(t, err, bad)
	}
}

// oobServer accepts one connection and returns everything it reads from it.
func oobServer(t *testing.T, inline bool) (addr string, result chan []byte) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	result = make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(result)
			return
		}
		defer conn.Close()
		if inline { // keep the urgent bytes in the stream to see them
			rawConn, _ := conn.(*net.TCPConn).SyscallConn()
			_ = rawConn.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1)
			})
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		data, _ := io.ReadAll(conn)
		result <- data
	}()
	return ln.Addr().String(), result
}

func TestOOBConn(t *testing.T) {
	steps, err := ParseOOB("65,_,66")
	require.NoError(t, err)

	for _, inline := range []bool{false, true} {
		addr, result := oobServer(t, inline)
		// the conn of the real dialer must be usable
		raw, err := dialer.DialContext(context.Background(), "tcp", addr)
		require.NoError(t, err)
		conn := NewOOBConn(raw, steps)
		oobConn, ok := conn.(*OOBConn)
		require.True(t, ok, "%T", conn)

		for _, data := range []string{"first", "second", "third", "fourth"} {
			assert.Equal(t, data != "fourth", !oobConn.WriterReplaceable())
			n, err := conn.Write([]byte(data))
			require.NoError(t, err)
			assert.Equal(t, len(data), n)
			time.Sleep(50 * time.Millisecond) // let the peer see each urgent byte
		}
		require.NoError(t, conn.Close())

		if inline {
			assert.Equal(t, "firstAsecondthirdBfourth", string(<-result))
		} else { // a normal peer never sees the extra bytes
			assert.Equal(t, "firstsecondthirdfourth", string(<-result))
		}
	}
}

func TestOOBConnNotSocket(t *testing.T) {
	steps, err := ParseOOB("0")
	require.NoError(t, err)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	assert.Equal(t, c1, NewOOBConn(c1, steps))

	// through the dialer with fragment on top
	config, err := ParseConfig(Options{Packets: "1", Length: "2", Interval: "0"})
	require.NoError(t, err)
	addr, result := oobServer(t, true)
	d := NewDialer(dialer.NewDialer(), config, []OOBStep{{Byte: 'x'}, {Byte: 'y'}})
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	require.NoError(t, err)
	_, err = conn.Write([]byte("abcd"))
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, conn.Close())
	// every fragment is a write for the oob conn
	assert.Equal(t, "abxcdy", string(<-result))
}
