package tunnel

import (
	"io"

	"github.com/Dreamacro/clash/adapters/local"
	C "github.com/Dreamacro/clash/constant"
)

func (t *Tunnel) handleHTTP(request *adapters.HTTPAdapter, proxy C.ProxyAdapter) {
	conn := newTrafficTrack(proxy.Conn(), t.traffic)

	// Before we unwrap src and/or dst, copy any buffered data.
	if wc, ok := request.Conn().(*adapters.PeekedConn); ok && len(wc.Peeked) > 0 {
		if _, err := conn.Write(wc.Peeked); err != nil {
			return
		}
		wc.Peeked = nil
	}

	go io.Copy(request.Conn(), conn)
	io.Copy(conn, request.Conn())
}

func (t *Tunnel) handleSOCKS(request *adapters.SocksAdapter, proxy C.ProxyAdapter) {
	conn := newTrafficTrack(proxy.Conn(), t.traffic)
	go io.Copy(request.Conn(), conn)
	io.Copy(conn, request.Conn())
}
