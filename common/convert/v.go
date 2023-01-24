package convert

import (
	"errors"
	"net/url"
	"strings"
)

func handleVShareLink(names map[string]int, url *url.URL, scheme string, proxy map[string]any) error {
	// Xray VMessAEAD / VLESS share link standard
	// https://github.com/XTLS/Xray-core/discussions/716
	query := url.Query()
	proxy["name"] = uniqueName(names, url.Fragment)
	if url.Hostname() == "" {
		return errors.New("url.Hostname() is empty")
	}
	if url.Port() == "" {
		return errors.New("url.Port() is empty")
	}
	proxy["type"] = scheme
	proxy["server"] = url.Hostname()
	proxy["port"] = url.Port()
	proxy["uuid"] = url.User.Username()
	proxy["udp"] = true
	proxy["skip-cert-verify"] = false
	proxy["tls"] = false
	tls := strings.ToLower(query.Get("security"))
	if strings.HasSuffix(tls, "tls") {
		proxy["tls"] = true
	}
	if sni := query.Get("sni"); sni != "" {
		proxy["servername"] = sni
	}

	switch query.Get("packetEncoding") {
	case "none":
	case "packet":
		proxy["packet-addr"] = true
	default:
		proxy["xudp"] = true
	}

	network := strings.ToLower(query.Get("type"))
	if network == "" {
		network = "tcp"
	}
	fakeType := strings.ToLower(query.Get("headerType"))
	if fakeType == "http" {
		network = "http"
	} else if network == "http" {
		network = "h2"
	}
	proxy["network"] = network
	switch network {
	case "tcp":
		if fakeType != "none" {
			headers := make(map[string]any)
			httpOpts := make(map[string]any)
			httpOpts["path"] = []string{"/"}

			if host := query.Get("host"); host != "" {
				headers["Host"] = []string{host}
			}

			if method := query.Get("method"); method != "" {
				httpOpts["method"] = method
			}

			if path := query.Get("path"); path != "" {
				httpOpts["path"] = []string{path}
			}
			httpOpts["headers"] = headers
			proxy["http-opts"] = httpOpts
		}

	case "http":
		headers := make(map[string]any)
		h2Opts := make(map[string]any)
		h2Opts["path"] = []string{"/"}
		if path := query.Get("path"); path != "" {
			h2Opts["path"] = []string{path}
		}
		if host := query.Get("host"); host != "" {
			h2Opts["host"] = []string{host}
		}
		h2Opts["headers"] = headers
		proxy["h2-opts"] = h2Opts

	case "ws":
		headers := make(map[string]any)
		wsOpts := make(map[string]any)
		headers["User-Agent"] = RandUserAgent()
		headers["Host"] = query.Get("host")
		wsOpts["path"] = query.Get("path")
		wsOpts["headers"] = headers

		proxy["ws-opts"] = wsOpts

	case "grpc":
		grpcOpts := make(map[string]any)
		grpcOpts["grpc-service-name"] = query.Get("serviceName")
		proxy["grpc-opts"] = grpcOpts
	}
	return nil
}
