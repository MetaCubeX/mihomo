package inbound

import (
	"net"
	"net/http"

	C "github.com/Dreamacro/clash/constant"
)

// NewHTTPS receive CONNECT request and return ConnContext
func NewHTTPS(request *http.Request, conn net.Conn, additions ...Addition) (net.Conn, *C.Metadata) {
	metadata := parseHTTPAddr(request)
	metadata.Type = C.HTTPS
	additions = append(additions, WithSrcAddr(conn.RemoteAddr()), WithInAddr(conn.LocalAddr()))
	for _, addition := range additions {
		addition.Apply(metadata)
	}
	return conn, metadata
}
