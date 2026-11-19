package adapter

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
)

func lastRecord(t *testing.T, p *Proxy, url string) (history, extra string, delay uint16) {
	t.Helper()
	h := p.DelayHistory()
	e := p.DelayHistoryForTestUrl(url)
	if len(h) == 0 || len(e) == 0 {
		t.Fatal("no delay history recorded")
	}
	return h[len(h)-1].Error, e[len(e)-1].Error, e[len(e)-1].Delay
}

func TestURLTestRecordsWhyItFailed(t *testing.T) {
	t.Run("passed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()
		p := NewProxy(outbound.NewDirect())
		if _, err := p.URLTest(context.Background(), srv.URL, nil); err != nil {
			t.Fatal(err)
		}
		history, extra, delay := lastRecord(t, p, srv.URL)
		if history != "" || extra != "" || delay == 0 {
			t.Fatalf("passed test recorded error %q / %q, delay %d", history, extra, delay)
		}
	})

	t.Run("refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		url := "http://" + l.Addr().String() + "/"
		_ = l.Close()
		p := NewProxy(outbound.NewDirect())
		_, _ = p.URLTest(context.Background(), url, nil)
		history, extra, _ := lastRecord(t, p, url)
		if !strings.Contains(history, "refused") || history != extra {
			t.Fatalf("got %q / %q", history, extra)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() { // accept and never answer
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
			}
		}()
		url := "http://" + l.Addr().String() + "/"
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		p := NewProxy(outbound.NewDirect())
		_, _ = p.URLTest(ctx, url, nil)
		history, _, _ := lastRecord(t, p, url)
		if !strings.Contains(history, "deadline exceeded") && !strings.Contains(history, "timeout") {
			t.Fatalf("got %q", history)
		}
	})

	t.Run("reset", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() { // read the request, then close with a RST
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_ = c.(*net.TCPConn).SetLinger(0)
				_ = c.Close()
			}
		}()
		url := "http://" + l.Addr().String() + "/"
		p := NewProxy(outbound.NewDirect())
		_, _ = p.URLTest(context.Background(), url, nil)
		history, _, _ := lastRecord(t, p, url)
		// How a reset reads varies by OS: "connection reset by peer", "EOF", or on Windows
		// "An existing connection was forcibly closed by the remote host".
		if !strings.Contains(history, "reset") && !strings.Contains(history, "EOF") &&
			!strings.Contains(history, "forcibly closed") {
			t.Fatalf("got %q", history)
		}
	})

	t.Run("unexpected status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		want, err := utils.NewUnsignedRanges[uint16]("204")
		if err != nil {
			t.Fatal(err)
		}
		p := NewProxy(outbound.NewDirect())
		_, _ = p.URLTest(context.Background(), srv.URL, want)
		history, extra, delay := lastRecord(t, p, srv.URL)
		// the overall history counts any answer as a pass, as before
		if history != "" || extra != "unexpected status code" || delay != 0 {
			t.Fatalf("got %q / %q, delay %d", history, extra, delay)
		}
	})
}
