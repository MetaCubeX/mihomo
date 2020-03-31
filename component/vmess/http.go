package vmess

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/textproto"
)

type httpConn struct {
	net.Conn
	cfg        *HTTPConfig
	rhandshake bool
	whandshake bool
}

type HTTPConfig struct {
	Method  string
	Host    string
	Path    []string
	Headers map[string][]string
}

// Read implements net.Conn.Read()
func (hc *httpConn) Read(b []byte) (int, error) {
	if hc.rhandshake {
		n, err := hc.Conn.Read(b)
		return n, err
	}

	reader := textproto.NewConn(hc.Conn)
	// First line: GET /index.html HTTP/1.0
	if _, err := reader.ReadLine(); err != nil {
		return 0, err
	}

	if _, err := reader.ReadMIMEHeader(); err != nil {
		return 0, err
	}

	hc.rhandshake = true
	return hc.Conn.Read(b)
}

// Write implements io.Writer.
func (hc *httpConn) Write(b []byte) (int, error) {
	if hc.whandshake {
		return hc.Conn.Write(b)
	}

	path := hc.cfg.Path[rand.Intn(len(hc.cfg.Path))]
	u := fmt.Sprintf("http://%s%s", hc.cfg.Host, path)
	req, _ := http.NewRequest("GET", u, bytes.NewBuffer(b))
	for key, list := range hc.cfg.Headers {
		req.Header.Set(key, list[rand.Intn(len(list))])
	}
	req.ContentLength = int64(len(b))
	if err := req.Write(hc.Conn); err != nil {
		return 0, err
	}
	hc.whandshake = true
	return len(b), nil
}

func (hc *httpConn) Close() error {
	return hc.Conn.Close()
}

func StreamHTTPConn(conn net.Conn, cfg *HTTPConfig) net.Conn {
	return &httpConn{
		Conn: conn,
		cfg:  cfg,
	}
}
