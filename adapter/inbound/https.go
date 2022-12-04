package inbound

import (
	"net"
	"net/http"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
)

// NewHTTPS receive CONNECT request and return ConnContext
func NewHTTPS(request *http.Request, conn net.Conn) *context.ConnContext {
	return NewHTTPSWithInfos(request, conn, "", "")
}

func NewHTTPSWithInfos(request *http.Request, conn net.Conn, inName, specialRules string) *context.ConnContext {
	metadata := parseHTTPAddr(request)
	metadata.Type = C.HTTPS
	metadata.SpecialRules = specialRules
	metadata.InName = inName
	if ip, port, err := parseAddr(conn.RemoteAddr().String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}
	if ip, port, err := parseAddr(conn.LocalAddr().String()); err == nil {
		metadata.InIP = ip
		metadata.InPort = port
	}
	return context.NewConnContext(conn, metadata)
}
