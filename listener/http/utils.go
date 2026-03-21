package http

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/http"
)

// removeHopByHopHeaders remove Proxy-* headers
func removeProxyHeaders(header http.Header) {
	header.Del("Proxy-Connection")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
}

// removeHopByHopHeaders remove hop-by-hop header
func removeHopByHopHeaders(header http.Header) {
	// Strip hop-by-hop header based on RFC:
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
	// https://www.mnot.net/blog/2011/07/11/what_proxies_must_do

	removeProxyHeaders(header)

	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")

	connections := header.Get("Connection")
	header.Del("Connection")
	if len(connections) == 0 {
		return
	}
	for _, h := range strings.Split(connections, ",") {
		header.Del(strings.TrimSpace(h))
	}
}

// removeExtraHTTPHostPort remove extra host port (example.com:80 --> example.com)
// It resolves the behavior of some HTTP servers that do not handle host:80 (e.g. baidu.com)
func removeExtraHTTPHostPort(req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	if pHost, port, err := net.SplitHostPort(host); err == nil && port == "80" {
		host = pHost
		if ip, err := netip.ParseAddr(pHost); err == nil && ip.Is6() {
			// RFC 2617 Sec 3.2.2, for IPv6 literal
			// addresses the Host header needs to follow the RFC 2732 grammar for "host"
			host = "[" + host + "]"
		}
	}

	req.Host = host
	req.URL.Host = host
}

// parseBasicProxyAuthorization parse header Proxy-Authorization and return base64-encoded credential
func parseBasicProxyAuthorization(request *http.Request) string {
	value := request.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	// According to RFC7617, the scheme should be case-insensitive.
	// In practice, some implementations do use different case styles, causing authentication to fail
	// eg: https://github.com/algesten/ureq/blob/381fd42cfcb80a5eb709d64860aa0ae726f17b8e/src/unversioned/transport/connect.rs#L118
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}

	return value[6:] // value[len("Basic "):]
}

// decodeBasicProxyAuthorization decode base64-encoded credential
func decodeBasicProxyAuthorization(credential string) (string, string, error) {
	plain, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		return "", "", err
	}

	user, pass, found := strings.Cut(string(plain), ":")
	if !found {
		return "", "", errors.New("invalid login")
	}

	return user, pass, nil
}
