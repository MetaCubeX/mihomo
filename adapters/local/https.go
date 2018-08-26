package adapters

import (
	"net"
	"net/http"
)

// NewHTTPS is HTTPAdapter generator
func NewHTTPS(request *http.Request, conn net.Conn) *SocketAdapter {
	return &SocketAdapter{
		addr: parseHTTPAddr(request),
		conn: conn,
	}
}
