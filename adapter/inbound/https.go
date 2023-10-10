package inbound

import (
	"net"
	"net/http"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
)

// NewHTTPS receive CONNECT request and return ConnContext
func NewHTTPS(request *http.Request, conn net.Conn, additions ...Addition) *context.ConnContext {
	metadata := parseHTTPAddr(request)
	metadata.Type = C.HTTPS
	additions = append(additions, WithSrcAddr(conn.RemoteAddr()), WithInAddr(conn.LocalAddr()))
	for _, addition := range additions {
		addition.Apply(metadata)
	}
	return context.NewConnContext(conn, metadata)
}
