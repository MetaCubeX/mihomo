package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
)

func TestProxyURLTestExpectedBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("hello world"))
	})
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		// simulate a soft-blocked exit: normal status code, but the content
		// indicates the node is unusable (e.g. region restricted page)
		_, _ = w.Write([]byte("region is not supported"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewProxy(outbound.NewDirect())

	test := func(url string, expectedBody string, excludeBody string, wantAlive bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := p.URLTest(ctx, url, nil, expectedBody, excludeBody)
		if err != nil {
			t.Fatalf("URLTest(%q, %q, %q) error: %v", url, expectedBody, excludeBody, err)
		}
		if alive := p.AliveForTestUrl(url); alive != wantAlive {
			t.Fatalf("URLTest(%q, %q, %q) alive = %v, want %v", url, expectedBody, excludeBody, alive, wantAlive)
		}
	}

	// no expected body: alive
	test(srv.URL+"/ok", "", "", true)
	// expected body contained in the response: alive
	test(srv.URL+"/ok", "world", "", true)
	// expected body missing from the response: not alive
	test(srv.URL+"/blocked", "hello world", "", false)
	// multiple expected keywords, any match keeps the node alive
	test(srv.URL+"/ok", "hello`golang", "", true)
	// exclude keyword hit: not alive even though status is fine
	test(srv.URL+"/blocked", "", "not supported", false)
	// exclude keyword absent: alive
	test(srv.URL+"/blocked", "", "unavailable", true)
	// exclude wins over expected: body contains both, must be marked dead
	test(srv.URL+"/blocked", "region", "not supported", false)
}
