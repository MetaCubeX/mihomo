package xhttp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/http/httptrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureRoundTripper chan *http.Request

func (c captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c <- req
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
		conn, peer := net.Pipe()
		trace.GotConn(httptrace.GotConnInfo{Conn: conn})
		_ = conn.Close()
		_ = peer.Close()
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}, nil
}

func TestClientPathWithQuery(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			requests := make(captureRoundTripper, 4)
			cfg := &Config{Host: "example.com", Path: "/xhttp?ed=2560&token=x", Mode: mode}
			client, err := NewClient(cfg, func() http.RoundTripper { return requests }, nil, false)
			require.NoError(t, err)
			defer client.Close()

			conn, err := client.Dial(context.Background())
			require.NoError(t, err)
			defer conn.Close()

			count := 2 // download and upload
			switch mode {
			case "stream-one":
				count = 1
			case "packet-up":
				_, err = conn.Write([]byte("ping"))
				require.NoError(t, err)
			}
			for i := 0; i < count; i++ {
				select {
				case req := <-requests:
					assert.Regexp(t, `^/xhttp/[^?]*$`, req.URL.Path)
					assert.Equal(t, "ed=2560&token=x", req.URL.RawQuery)
				case <-time.After(5 * time.Second):
					t.Fatal("request not sent")
				}
			}
		})
	}
}

func TestServerPathWithQuery(t *testing.T) {
	config := Config{Path: "/xhttp?ed=2560", Mode: "stream-one"}
	handler, err := NewServerHandler(ServerOption{
		Config: config,
		ConnHandler: func(conn net.Conn) {
			_ = conn.Close()
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://example.com/xhttp/?ed=2560", io.NopCloser(http.NoBody))
	require.NoError(t, config.FillStreamRequest(req, ""))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
}
