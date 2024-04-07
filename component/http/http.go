package http

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	URL "net/url"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
)

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader, specialProxy string) (*http.Response, error) {
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
		req.Header.Set("User-Agent", C.UA)
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
		DisableKeepAlives:     runtime.GOOS == "android",
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if conn, err := inner.HandleTcp(address, specialProxy); err == nil {
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
