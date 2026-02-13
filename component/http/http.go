package http

import (
	"context"
	"io"
	"net"
	URL "net/url"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/listener/inner"

	"github.com/metacubex/http"
)

var (
	ua string
)

func UA() string {
	return ua
}

func SetUA(UA string) {
	ua = UA
}

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader, options ...Option) (*http.Response, error) {
	opt := option{}
	for _, o := range options {
		o(&opt)
	}
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	if err != nil {
		return nil, err
	}

	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", UA())
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(opt.caOption)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		// from http.DefaultTransport
		DisableKeepAlives:     runtime.GOOS == "android",
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if conn, err := inner.HandleTcp(inner.GetTunnel(), address, opt.specialProxy); err == nil {
				return conn, nil
			} else {
				return dialer.DialContext(ctx, network, address)
			}
		},
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{Transport: transport}
	return client.Do(req)
}

type Option func(opt *option)

type option struct {
	specialProxy string
	caOption     ca.Option
}

func WithSpecialProxy(name string) Option {
	return func(opt *option) {
		opt.specialProxy = name
	}
}

func WithCAOption(caOption ca.Option) Option {
	return func(opt *option) {
		opt.caOption = caOption
	}
}
