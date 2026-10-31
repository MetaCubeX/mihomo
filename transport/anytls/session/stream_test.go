package session

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

func TestStreamConcurrentCloseIO(t *testing.T) {
	session := NewServerSession(discardConn{}, nil, nil)
	stream := newStream(1, session)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, action := range []func(){
		func() {
			_ = stream.SetReadDeadline(time.Now().Add(-time.Second))
			for i := 0; i < 1000; i++ {
				_, _ = stream.Read(make([]byte, 1))
			}
		},
		func() {
			for i := 0; i < 1000; i++ {
				_, _ = stream.Write([]byte("data"))
			}
		},
		func() { stream.closeLocally() },
	} {
		action := action
		wg.Add(1)
		go func() { defer wg.Done(); <-start; action() }()
	}
	close(start)
	wg.Wait()
	_, err := stream.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = stream.Write([]byte("closed"))
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestStreamCloseHookRegistration(t *testing.T) {
	for _, when := range []string{"before", "after", "concurrent"} {
		t.Run(when, func(t *testing.T) {
			stream := newStream(1, nil)
			var calls atomic.Int32
			hook := func() {
				calls.Add(1)
				// Reentrancy must not deadlock on the hook or sync.Once lock.
				_ = stream.Close()
			}
			switch when {
			case "before":
				stream.setCloseHook(hook)
				stream.closeLocally()
			case "after":
				stream.closeLocally()
				stream.setCloseHook(hook)
			default:
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); stream.setCloseHook(hook) }()
				go func() { defer wg.Done(); stream.closeLocally() }()
				wg.Wait()
			}
			stream.closeLocally()
			require.EqualValues(t, 1, calls.Load())
		})
	}
}

func TestStreamRemoteErrorSurvivesClose(t *testing.T) {
	session := NewServerSession(discardConn{}, nil, nil)
	stream := newStream(1, session)
	require.NoError(t, stream.closeWithError(io.ErrUnexpectedEOF))
	require.ErrorIs(t, stream.Close(), io.ErrUnexpectedEOF)
	_, err := stream.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = stream.Write([]byte("closed"))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
