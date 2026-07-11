package httpmask

import (
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
)

func TestSessionPreconnectCount(t *testing.T) {
	for _, test := range []struct {
		mode string
		want int
	}{
		{mode: "off", want: tunnelPreconnectCount},
		{mode: "auto", want: tunnelPreconnectCount},
		{mode: "on", want: tunnelMuxPreconnectCount},
	} {
		if got := sessionPreconnectCount(test.mode); got != test.want {
			t.Fatalf("sessionPreconnectCount(%q) = %d, want %d", test.mode, got, test.want)
		}
	}
}

func TestDialSessionPreconnectsMuxSpare(t *testing.T) {
	var dialer *preconnectDialer
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		if !waitForPreparedConns(dialer, tunnelMuxPreconnectCount-1, 2*time.Second) {
			stdhttp.Error(w, "mux preconnections not ready", stdhttp.StatusGatewayTimeout)
			return
		}
		_, _ = io.WriteString(w, "token=preconnected")
	}))
	defer server.Close()

	serverAddress := strings.TrimPrefix(server.URL, "http://")
	opts := TunnelDialOptions{
		Mode:      string(TunnelModeStream),
		Multiplex: "on",
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	client, createdDialer, target, err := newHTTPClient(serverAddress, opts, 4)
	if err != nil {
		t.Fatalf("new HTTP client: %v", err)
	}
	dialer = createdDialer
	transport := client.Transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	defer dialer.close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialSessionWithClient(ctx, client, dialer, target, TunnelModeStream, opts); err != nil {
		t.Fatalf("dial session: %v", err)
	}
	if !waitForPreparedConns(dialer, tunnelMuxPreconnectCount-1, time.Second) {
		t.Fatal("mux spare preconnection was not retained")
	}
}

func waitForPreparedConns(dialer *preconnectDialer, count int, timeout time.Duration) bool {
	if dialer == nil || dialer.pool == nil {
		return false
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		dialer.pool.mu.Lock()
		ready := len(dialer.pool.ready)
		dialer.pool.mu.Unlock()
		if ready >= count {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
