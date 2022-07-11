package http

import (
	"context"
	"github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/listener/inner"
	"io"
	"net"
	"net/http"
	URL "net/url"
	"strings"
	"time"
)

const (
	UA = "Clash"
)

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader) (*http.Response, error) {
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
			conn := inner.HandleTcp(address, urlRes.Hostname())
			return conn, nil
		},
		TLSClientConfig: tls.GetDefaultTLSConfig(),
	}

	client := http.Client{Transport: transport}
	return client.Do(req)

}
