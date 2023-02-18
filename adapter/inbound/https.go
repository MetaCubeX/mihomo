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
	for _, addition := range additions {
		addition.Apply(metadata)
	}
	if ip, port, err := parseAddr(conn.RemoteAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}
	if ip, port, err := parseAddr(conn.LocalAddr()); err == nil {
		metadata.InIP = ip
		metadata.InPort = port
	}
	return context.NewConnContext(conn, metadata)
}
