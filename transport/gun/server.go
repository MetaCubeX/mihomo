package gun

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const idleTimeout = 30 * time.Second

type ServerOption struct {
	ServiceName string
	ConnHandler func(conn net.Conn)
	HttpHandler http.Handler
}

func NewServerHandler(options ServerOption) http.Handler {
	path := "/" + options.ServiceName + "/Tun"
	connHandler := options.ConnHandler
	httpHandler := options.HttpHandler
	if httpHandler == nil {
		httpHandler = http.NewServeMux()
	}
	// using h2c.NewHandler to ensure we can work in plain http2
	// and some tls conn is not *tls.Conn (like *reality.Conn)
	return h2c.NewHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == path &&
			request.Method == http.MethodPost &&
			strings.HasPrefix(request.Header.Get("Content-Type"), "application/grpc") {

			writer.Header().Set("Content-Type", "application/grpc")
			writer.Header().Set("TE", "trailers")
			writer.WriteHeader(http.StatusOK)

			conn := &Conn{
				initFn: func() (io.ReadCloser, error) {
					return request.Body, nil
				},
				writer:  writer,
				flusher: writer.(http.Flusher),
			}
			if request.RemoteAddr != "" {
				metadata := C.Metadata{}
				if err := metadata.SetRemoteAddress(request.RemoteAddr); err == nil {
					conn.remoteAddr = net.TCPAddrFromAddrPort(metadata.AddrPort())
				}
			}
			if addr, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
				conn.localAddr = addr
			}

			// gun.Conn can't correct handle ReadDeadline
			// so call N.NewDeadlineConn to add a safe wrapper
			connHandler(N.NewDeadlineConn(conn))
			return
		}

		httpHandler.ServeHTTP(writer, request)
	}), &http2.Server{
		IdleTimeout: idleTimeout,
	})
}
