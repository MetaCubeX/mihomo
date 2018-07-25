package tunnel

import (
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Dreamacro/clash/adapters/local"
	C "github.com/Dreamacro/clash/constant"
)

func (t *Tunnel) handleHTTP(request *adapters.HttpAdapter, proxy C.ProxyAdapter) {
	req := http.Transport{
		Dial: func(string, string) (net.Conn, error) {
			conn := newTrafficTrack(proxy.Conn(), t.traffic)
			return conn, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	resp, err := req.RoundTrip(request.R)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	header := request.W.Header()
	for k, vv := range resp.Header {
		for _, v := range vv {
			header.Add(k, v)
		}
	}
	request.W.WriteHeader(resp.StatusCode)
	var writer io.Writer = request.W
	if len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
		writer = ChunkWriter{Writer: request.W}
	}
	io.Copy(writer, resp.Body)
}

func (t *Tunnel) handleHTTPS(request *adapters.HttpsAdapter, proxy C.ProxyAdapter) {
	conn := newTrafficTrack(proxy.Conn(), t.traffic)
	go io.Copy(request.Conn(), conn)
	io.Copy(conn, request.Conn())
}

func (t *Tunnel) handleSOCKS(request *adapters.SocksAdapter, proxy C.ProxyAdapter) {
	conn := newTrafficTrack(proxy.Conn(), t.traffic)
	go io.Copy(request.Conn(), conn)
	io.Copy(conn, request.Conn())
}

// ChunkWriter is a writer wrapper and used when TransferEncoding is chunked
type ChunkWriter struct {
	io.Writer
}

func (cw ChunkWriter) Write(b []byte) (int, error) {
	n, err := cw.Writer.Write(b)
	if err == nil {
		cw.Writer.(http.Flusher).Flush()
	}
	return n, err
}
