package tunnel

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Dreamacro/clash/adapters/inbound"
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
		err = resp.Write(request.Conn())
		if err != nil || resp.Close {
			break
		}

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
	relay(request.Conn(), conn)
}

// relay copies between left and right bidirectionally.
func relay(leftConn, rightConn net.Conn) {
	ch := make(chan error)

	go func() {
		_, err := io.Copy(leftConn, rightConn)
		leftConn.SetReadDeadline(time.Now())
		ch <- err
	}()

	io.Copy(rightConn, leftConn)
	rightConn.SetReadDeadline(time.Now())
	<-ch
}
