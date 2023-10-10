package inbound

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewHTTP receive normal http request and return HTTPContext
func NewHTTP(target socks5.Addr, source net.Addr, conn net.Conn, additions ...Addition) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = C.HTTP
	additions = append(additions, WithSrcAddr(source), WithInAddr(conn.LocalAddr()))
	for _, addition := range additions {
		addition.Apply(metadata)
	}
	return context.NewConnContext(conn, metadata)
}
