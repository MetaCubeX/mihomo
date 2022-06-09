package gun

import (
	"net"

	"golang.org/x/net/http2"
)

type TransportWrap struct {
	*http2.Transport
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (tw *TransportWrap) RemoteAddr() net.Addr {
	return tw.remoteAddr
}

func (tw *TransportWrap) LocalAddr() net.Addr {
	return tw.localAddr
}
