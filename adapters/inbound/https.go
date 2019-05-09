package adapters

import (
	"net"
	"net/http"
)

// NewHTTPS is HTTPAdapter generator
func NewHTTPS(request *http.Request, conn net.Conn) *SocketAdapter {
	metadata := parseHTTPAddr(request)
	if ip, port, err := parseAddr(conn.RemoteAddr().String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}
	return &SocketAdapter{
		metadata: metadata,
		Conn:     conn,
	}
}
