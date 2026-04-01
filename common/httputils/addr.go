package httputils

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
)

type NetAddr struct {
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (addr NetAddr) RemoteAddr() net.Addr {
	return addr.remoteAddr
}

func (addr NetAddr) LocalAddr() net.Addr {
	return addr.localAddr
}

func SetAddrFromRequest(addr *NetAddr, request *http.Request) {
	if request.RemoteAddr != "" {
		metadata := C.Metadata{}
		if err := metadata.SetRemoteAddress(request.RemoteAddr); err == nil {
			addr.remoteAddr = net.TCPAddrFromAddrPort(metadata.AddrPort())
		}
	}
	if netAddr, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		addr.localAddr = netAddr
	}
}

func NewAddrContext(addr *NetAddr, ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			addr.localAddr = connInfo.Conn.LocalAddr()
			addr.remoteAddr = connInfo.Conn.RemoteAddr()
		},
	})
}
