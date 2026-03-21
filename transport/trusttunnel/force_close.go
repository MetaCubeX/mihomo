package trusttunnel

import (
	"github.com/metacubex/mihomo/transport/gun"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
)

func forceCloseAllConnections(roundTripper RoundTripper) {
	roundTripper.CloseIdleConnections()
	switch tr := roundTripper.(type) {
	case *http.Http2Transport:
		gun.CloseTransport(tr)
	case *http3.Transport:
		_ = tr.Close()
	}
}
