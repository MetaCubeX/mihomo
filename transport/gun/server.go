package gun

import (
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
	"github.com/metacubex/http/h2c"
)

const idleTimeout = 30 * time.Second

type ServerOption struct {
	ServiceName string
	ConnHandler func(conn net.Conn)
	HttpHandler http.Handler
}

func NewServerHandler(options ServerOption) http.Handler {
	path := ServiceNameToPath(options.ServiceName)
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
				initFn: func() (io.ReadCloser, NetAddr, error) {
					nAddr := NetAddr{}
					nAddr.SetAddrFromRequest(request)
					return request.Body, nAddr, nil
				},
				writer: writer,
			}
			_ = conn.Init()

			wrapper := &h2ConnWrapper{
				// gun.Conn can't correct handle ReadDeadline
				// so call N.NewDeadlineConn to add a safe wrapper
				ExtendedConn: N.NewDeadlineConn(conn),
			}
			connHandler(wrapper)
			wrapper.CloseWrapper()

			return
		}

		httpHandler.ServeHTTP(writer, request)
	}), &http.Http2Server{
		IdleTimeout: idleTimeout,
	})
}

// h2ConnWrapper used to avoid "panic: Write called after Handler finished" for gun.Conn
type h2ConnWrapper struct {
	N.ExtendedConn
	access sync.Mutex
	closed bool
}

func (w *h2ConnWrapper) Write(p []byte) (n int, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	return w.ExtendedConn.Write(p)
}

func (w *h2ConnWrapper) WriteBuffer(buffer *buf.Buffer) error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	return w.ExtendedConn.WriteBuffer(buffer)
}

func (w *h2ConnWrapper) CloseWrapper() {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
}

func (w *h2ConnWrapper) Close() error {
	w.CloseWrapper()
	return w.ExtendedConn.Close()
}

func (w *h2ConnWrapper) Upstream() any {
	return w.ExtendedConn
}
