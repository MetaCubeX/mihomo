package xhttp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/http2"
)

// Read the actual client SETTINGS, rather than just inspecting the Go field:
// a value silently rejected by the HTTP/2 implementation would fail this test.
func TestH2ReceiveWindowSettings(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		want       uint32
	}{
		{"default", 0, 4 << 20},
		{"8MiB", 8 << 20, 8 << 20},
		{"16MiB", 16 << 20, 16 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			server.SetDeadline(time.Now().Add(5 * time.Second))
			rt := NewTransport(func(context.Context) (net.Conn, error) { return client, nil },
				func(_ context.Context, c net.Conn, _ bool) (net.Conn, error) { return c, nil },
				nil, []string{"h2"}, -1, tc.configured).(*http.Transport)
			defer rt.CloseIdleConnections()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.test/", nil)
				resp, _ := rt.RoundTrip(req)
				if resp != nil {
					resp.Body.Close()
				}
			}()
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(server, preface); err != nil {
				t.Fatal(err)
			}
			if string(preface) != http2.ClientPreface {
				t.Fatal("missing HTTP/2 client preface")
			}
			frame, err := http2.NewFramer(server, server).ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			settings, ok := frame.(*http2.SettingsFrame)
			if !ok {
				t.Fatalf("first frame is %T", frame)
			}
			got, ok := settings.Value(http2.SettingInitialWindowSize)
			if !ok || got != tc.want {
				t.Fatalf("INITIAL_WINDOW_SIZE = %d (present %v), want %d", got, ok, tc.want)
			}
			cancel()
			client.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not stop")
			}
		})
	}
}
