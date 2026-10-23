package route

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// A delay test must stop when the API request is cancelled instead of
// running on to its own timeout.
func TestGetProxyDelayRequestCancelled(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // accept the request and never answer
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var proxy C.Proxy = adapter.NewProxy(outbound.NewDirect())
	req := httptest.NewRequest(http.MethodGet, "/proxies/DIRECT/delay?timeout=8000&url="+url.QueryEscape(server.URL), nil)
	req = req.WithContext(context.WithValue(ctx, CtxKeyProxy, proxy))

	done := make(chan struct{})
	go func() {
		defer close(done)
		getProxyDelay(httptest.NewRecorder(), req)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("delay test kept running after the request was cancelled")
	}
}
