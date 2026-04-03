package convert

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
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
	tls := strings.ToLower(query.Get("security"))
	if strings.HasSuffix(tls, "tls") || tls == "reality" {
		proxy["tls"] = true
		if fingerprint := query.Get("fp"); fingerprint == "" {
			proxy["client-fingerprint"] = "chrome"
		} else {
			proxy["client-fingerprint"] = fingerprint
		}
		if alpn := query.Get("alpn"); alpn != "" {
			proxy["alpn"] = strings.Split(alpn, ",")
		}
		if pcs := query.Get("pcs"); pcs != "" {
			proxy["fingerprint"] = pcs
		}
	}
	if sni := query.Get("sni"); sni != "" {
		proxy["servername"] = sni
	}
	if realityPublicKey := query.Get("pbk"); realityPublicKey != "" {
		proxy["reality-opts"] = map[string]any{
			"public-key": realityPublicKey,
			"short-id":   query.Get("sid"),
		}
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

	case "ws", "httpupgrade":
		headers := make(map[string]any)
		wsOpts := make(map[string]any)
		headers["User-Agent"] = RandUserAgent()
		headers["Host"] = query.Get("host")
		wsOpts["path"] = query.Get("path")
		wsOpts["headers"] = headers

		if earlyData := query.Get("ed"); earlyData != "" {
			med, err := strconv.Atoi(earlyData)
			if err != nil {
				return fmt.Errorf("bad WebSocket max early data size: %v", err)
			}
			switch network {
			case "ws":
				wsOpts["max-early-data"] = med
				wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
			case "httpupgrade":
				wsOpts["v2ray-http-upgrade-fast-open"] = true
			}
		}
		if earlyDataHeader := query.Get("eh"); earlyDataHeader != "" {
			wsOpts["early-data-header-name"] = earlyDataHeader
		}

		proxy["ws-opts"] = wsOpts

	case "grpc":
		grpcOpts := make(map[string]any)
		grpcOpts["grpc-service-name"] = query.Get("serviceName")
		proxy["grpc-opts"] = grpcOpts

	case "xhttp":
		proxy["network"] = "xhttp"
		xhttpOpts := make(map[string]any)

		if path := query.Get("path"); path != "" {
			xhttpOpts["path"] = path
		}

		if host := query.Get("host"); host != "" {
			xhttpOpts["host"] = host
		}

		if mode := query.Get("mode"); mode != "" {
			xhttpOpts["mode"] = mode
		}

		if extra := query.Get("extra"); extra != "" {
			var extraMap map[string]any
			if err := json.Unmarshal([]byte(extra), &extraMap); err == nil {
				parseXHTTPExtra(extraMap, xhttpOpts)
			}
		}

		proxy["xhttp-opts"] = xhttpOpts
	}

	return nil
}

// parseXHTTPExtra maps xray-core extra JSON fields to mihomo xhttp-opts fields.
func parseXHTTPExtra(extra map[string]any, opts map[string]any) {
	if v, ok := extra["noGRPCHeader"].(bool); ok && v {
		opts["no-grpc-header"] = true
	}

	if v, ok := extra["xPaddingBytes"].(string); ok && v != "" {
		opts["x-padding-bytes"] = v
	}

	if dsAny, ok := extra["downloadSettings"].(map[string]any); ok {
		ds := make(map[string]any)

		if addr, ok := dsAny["address"].(string); ok && addr != "" {
			ds["server"] = addr
		}

		if port, ok := dsAny["port"].(float64); ok {
			ds["port"] = int(port)
		}

		if sec, ok := dsAny["security"].(string); ok && strings.ToLower(sec) == "tls" {
			ds["tls"] = true
		}

		if tlsAny, ok := dsAny["tlsSettings"].(map[string]any); ok {
			if sn, ok := tlsAny["serverName"].(string); ok && sn != "" {
				ds["servername"] = sn
			}
			if fp, ok := tlsAny["fingerprint"].(string); ok && fp != "" {
				ds["client-fingerprint"] = fp
			}
			if alpnAny, ok := tlsAny["alpn"].([]any); ok && len(alpnAny) > 0 {
				alpnList := make([]string, 0, len(alpnAny))
				for _, a := range alpnAny {
					if s, ok := a.(string); ok {
						alpnList = append(alpnList, s)
					}
				}
				if len(alpnList) > 0 {
					ds["alpn"] = alpnList
				}
			}
		}

		if xhttpAny, ok := dsAny["xhttpSettings"].(map[string]any); ok {
			if path, ok := xhttpAny["path"].(string); ok && path != "" {
				ds["path"] = path
			}
			if host, ok := xhttpAny["host"].(string); ok && host != "" {
				ds["host"] = host
			}
			if v, ok := xhttpAny["noGRPCHeader"].(bool); ok && v {
				ds["no-grpc-header"] = true
			}
			if v, ok := xhttpAny["xPaddingBytes"].(string); ok && v != "" {
				ds["x-padding-bytes"] = v
			}
		}

		if len(ds) > 0 {
			opts["download-settings"] = ds
		}
	}
}