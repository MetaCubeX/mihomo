package httputils

import (
	"io"

	"github.com/metacubex/http"
)

type closeIdleTransport interface {
	CloseIdleConnections()
}

func CloseTransport(roundTripper http.RoundTripper) {
	if tr, ok := roundTripper.(closeIdleTransport); ok {
		tr.CloseIdleConnections() // for *http.Transport
	}
	if tr, ok := roundTripper.(*http.Http2Transport); ok {
		closeHttp2Transport(tr) // for *http2.Transport
	}
	if tr, ok := roundTripper.(io.Closer); ok {
		_ = tr.Close() // for *http3.Transport
	}
}
