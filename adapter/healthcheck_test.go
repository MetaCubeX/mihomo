package adapter

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/andybalholm/brotli"
	http "github.com/metacubex/http"
	"github.com/stretchr/testify/require"

	C "github.com/metacubex/mihomo/constant"
)

func TestHealthCheckResponseSatisfiedMatchesDecodedBody(t *testing.T) {
	body := []byte("region=HK; service=available")

	tests := []struct {
		name     string
		encoding string
		payload  []byte
	}{
		{name: "plain", payload: body},
		{name: "gzip", encoding: "gzip", payload: gzipHealthCheckBody(t, body)},
		{name: "brotli", encoding: "br", payload: brotliHealthCheckBody(t, body)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewReader(tt.payload)),
			}
			if tt.encoding != "" {
				resp.Header.Set("Content-Encoding", tt.encoding)
			}

			matched, err := healthCheckResponseSatisfied(resp, C.HealthCheckOption{
				ExpectedStatus:    nil,
				Method:            C.HealthCheckMethodGet,
				ExpectedBodyMatch: `(?i)region=hk`,
			})
			require.NoError(t, err)
			require.True(t, matched)
		})
	}
}

func TestHealthCheckResponseSatisfiedDecodesChainedContentEncoding(t *testing.T) {
	// The response is encoded as br first and gzip second, represented by the
	// Content-Encoding list in the order in which the encodings were applied.
	encoded := brotliHealthCheckBody(t, []byte("available"))
	encoded = gzipHealthCheckBody(t, encoded)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Encoding": []string{"br, gzip"}},
		Body:       io.NopCloser(bytes.NewReader(encoded)),
	}

	matched, err := healthCheckResponseSatisfied(resp, C.HealthCheckOption{
		Method:            C.HealthCheckMethodGet,
		ExpectedBodyMatch: "available",
	})
	require.NoError(t, err)
	require.True(t, matched)
}

func TestHealthCheckResponseSatisfiedRejectsUnsupportedEncoding(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Encoding": []string{"zstd"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("available"))),
	}

	matched, err := healthCheckResponseSatisfied(resp, C.HealthCheckOption{
		Method:            C.HealthCheckMethodGet,
		ExpectedBodyMatch: "available",
	})
	require.Error(t, err)
	require.False(t, matched)
}

func gzipHealthCheckBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, err := writer.Write(body)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

func brotliHealthCheckBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := brotli.NewWriter(&buffer)
	_, err := writer.Write(body)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}
