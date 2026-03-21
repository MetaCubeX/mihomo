package tls

import (
	"context"
	"net"
	"runtime/debug"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

func extractTlsHandshakeTimeoutFromServer(s *http.Server) time.Duration {
	var ret time.Duration
	for _, v := range [...]time.Duration{
		s.ReadHeaderTimeout,
		s.ReadTimeout,
		s.WriteTimeout,
	} {
		if v <= 0 {
			continue
		}
		if ret == 0 || v < ret {
			ret = v
		}
	}
	return ret
}

// NewListenerForHttps returns a net.Listener for (*http.Server).Serve()
// the "func (c *conn) serve(ctx context.Context)" in http\server.go
// only do tls handshake and check NegotiatedProtocol with std's *tls.Conn
// so we do the same logic to let http2 (not h2c) work fine
func NewListenerForHttps(l net.Listener, httpServer *http.Server, tlsConfig *Config) net.Listener {
	http2Server := &http.Http2Server{}
	_ = http.Http2ConfigureServer(httpServer, http2Server)
	return N.NewHandleContextListener(context.Background(), l, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		c := Server(conn, tlsConfig)

		tlsTO := extractTlsHandshakeTimeoutFromServer(httpServer)
		if tlsTO > 0 {
			dl := time.Now().Add(tlsTO)
			_ = conn.SetReadDeadline(dl)
			_ = conn.SetWriteDeadline(dl)
		}

		err := c.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		// Restore Conn-level deadlines.
		if tlsTO > 0 {
			_ = conn.SetReadDeadline(time.Time{})
			_ = conn.SetWriteDeadline(time.Time{})
		}

		if c.ConnectionState().NegotiatedProtocol == http.Http2NextProtoTLS {
			http2Server.ServeConn(c, &http.Http2ServeConnOpts{BaseConfig: httpServer})
			return nil, net.ErrClosed
		}
		return c, nil
	}, func(a any) {
		stack := debug.Stack()
		log.Errorln("https server panic: %s\n%s", a, stack)
	})
}
