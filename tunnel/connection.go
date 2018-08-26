package tunnel

import (
	"bufio"
	"io"
	"net/http"

	"github.com/Dreamacro/clash/adapters/local"
	C "github.com/Dreamacro/clash/constant"
)

func (t *Tunnel) handleHTTP(request *adapters.HTTPAdapter, proxy C.ProxyAdapter) {
	conn := newTrafficTrack(proxy.Conn(), t.traffic)
	req := request.R
	host := req.Host

	for {
		req.Header.Set("Connection", "close")
		req.RequestURI = ""
		adapters.RemoveHopByHopHeaders(req.Header)
		err := req.Write(conn)
		if err != nil {
			break
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			break
		}
		adapters.RemoveHopByHopHeaders(resp.Header)
		if resp.ContentLength >= 0 {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
			resp.Close = false
		} else {
			resp.Close = true
		}
		resp.Write(request.Conn())

		req, err = http.ReadRequest(bufio.NewReader(request.Conn()))
		if err != nil {
			break
		}

		// Sometimes firefox just open a socket to process multiple domains in HTTP
		// The temporary solution is close connection when encountering different HOST
		if req.Host != host {
			break
		}
	}
}

func (t *Tunnel) handleSOCKS(request *adapters.SocketAdapter, proxy C.ProxyAdapter) {
	conn := newTrafficTrack(proxy.Conn(), t.traffic)
	go io.Copy(request.Conn(), conn)
	io.Copy(conn, request.Conn())
}
