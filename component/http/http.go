package http

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	URL "net/url"
	"strings"
	"time"

	"github.com/Dreamacro/clash/component/ca"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/inner"
)

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader) (*http.Response, error) {
	UA := C.UA
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if _, ok := header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", UA)
	}

	if err != nil {
		return nil, err
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	transport := &http.Transport{
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if conn, err := inner.HandleTcp(address); err == nil {
				return conn, nil
			} else {
				d := net.Dialer{}
				return d.DialContext(ctx, network, address)
			}
		},
		TLSClientConfig: ca.GetGlobalTLSConfig(&tls.Config{}),
	}

	client := http.Client{Transport: transport}
	return client.Do(req)

}
