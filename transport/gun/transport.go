package gun

import (
	"context"
	"net"
	"sync"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

type TransportWrap struct {
	*http.Http2Transport
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func (tw *TransportWrap) Close() error {
	tw.closeOnce.Do(func() {
		tw.cancel()
		CloseTransport(tw.Http2Transport)
	})
	return nil
}

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

func (addr *NetAddr) SetAddrFromRequest(request *http.Request) {
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

func (addr *NetAddr) SetRemoteAddr(remoteAddr net.Addr) {
	addr.remoteAddr = remoteAddr
}

func (addr *NetAddr) SetLocalAddr(localAddr net.Addr) {
	addr.localAddr = localAddr
}
