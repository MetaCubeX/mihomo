//go:build go1.25

package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
)

func TestLifecycleTFOWaitingRead(t *testing.T) {
	t.Setenv("GODEBUG", "asynctimerchan=0")
	for _, outcome := range []string{"published", "failed", "closed", "pending"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				c := tfoTestConnection(t, ctx, cancel, func(context.Context, []byte) (net.Conn, error) {
					panic("the publication window is controlled directly")
				})
				raw, peer := net.Pipe()
				defer raw.Close()
				defer peer.Close()
				results := make(chan error, 4)
				for i := 0; i < cap(results); i++ {
					go func() {
						b := make([]byte, 1)
						n, err := c.Read(b)
						if err == nil && (n != 1 || b[0] != 'x') {
							err = errors.New("accepted connection returned unexpected data")
						}
						results <- err
					}()
				}
				synctest.Wait() // All readers observed no connection and are awaiting publication.

				expected := errors.New("dial failed")
				writeDone := make(chan error, 1)
				if outcome == "published" || outcome == "closed" {
					// Match dial's ready publication, before close(dialed). Cancellation
					// is the only selectable event, without relying on select randomness.
					c.mu.Lock()
					c.connection = raw
					c.flags.Store(tfoReady)
					c.mu.Unlock()
				}
				switch outcome {
				case "published":
					defer close(c.dialed)
					expected = nil
					go func() { _, err := peer.Write([]byte("xxxx")); writeDone <- err }()
				case "failed":
					c.mu.Lock()
					c.dialErr = expected
					c.mu.Unlock()
					close(c.dialed)
				case "closed":
					expected = io.ErrClosedPipe
					if err := c.Close(); err != nil {
						t.Fatal(err)
					}
					defer close(c.dialed)
				case "pending":
					expected = io.ErrUnexpectedEOF
					defer close(c.dialed)
				}
				cancel()
				for i := 0; i < cap(results); i++ {
					if err := <-results; !errors.Is(err, expected) {
						t.Errorf("waiting Read: got %v, want %v", err, expected)
					}
				}
				if outcome == "published" {
					_ = c.Close() // Also releases the writer when the old implementation fails.
					if err := <-writeDone; err != nil && !t.Failed() {
						t.Fatal(err)
					}
				}
				synctest.Wait()
			})
		})
	}
}
