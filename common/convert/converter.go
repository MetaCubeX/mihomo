package convert

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/log"
)

// ConvertsV2Ray convert V2Ray subscribe proxies data to mihomo proxies config
func ConvertsV2Ray(buf []byte) ([]map[string]any, error) {
	data := DecodeBase64(buf)

	rawLines := bytes.Split(data, []byte("\n"))

	proxies := make([]map[string]any, 0, len(rawLines))
	names := make(map[string]int, 200)
	appendProxy := func(proxy map[string]any, name string, line int) {
		if err := validateProxyEndpoint(proxy); err != nil {
			log.Warnln("skipping invalid %s proxy at line %d: %s", proxy["type"], line+1, err)
			return
		}
		proxy["name"] = uniqueName(names, name)
		proxies = append(proxies, proxy)
	}

	for index, raw := range rawLines {
		line := strings.TrimRight(string(raw), " \r")
		if line == "" {
			continue
		}

		scheme, body, found := strings.Cut(line, "://")
		if !found {
			continue
		}

		scheme = strings.ToLower(scheme)
		switch scheme {
		case "hysteria":
			urlHysteria, err := url.Parse(line)
			if err != nil {
				continue
			}

			query := urlHysteria.Query()
			name := urlHysteria.Fragment
			hysteria := make(map[string]any, 20)

			hysteria["type"] = scheme
			hysteria["server"] = urlHysteria.Hostname()
			hysteria["port"] = urlHysteria.Port()
			hysteria["sni"] = query.Get("peer")
			hysteria["obfs"] = query.Get("obfs")
			if alpn := query.Get("alpn"); alpn != "" {
				hysteria["alpn"] = strings.Split(alpn, ",")
			}
			hysteria["auth_str"] = query.Get("auth")
			hysteria["protocol"] = query.Get("protocol")
			up := query.Get("up")
			down := query.Get("down")
			if up == "" {
				up = query.Get("upmbps")
			}
			if down == "" {
				down = query.Get("downmbps")
			}
			hysteria["down"] = down
			hysteria["up"] = up
			hysteria["skip-cert-verify"], _ = strconv.ParseBool(query.Get("insecure"))

			appendProxy(hysteria, name, index)

		case "hysteria2", "hy2", "hysteria2+realm", "hy2+realm":
			realmMode := strings.HasSuffix(scheme, "+realm")
			hopLine, ports := splitHysteria2Ports(line)
			urlHysteria2, err := url.Parse(hopLine)
			if err != nil {
				continue
			}

			query := urlHysteria2.Query()
			name := urlHysteria2.Fragment
			hysteria2 := make(map[string]any, 20)

			hysteria2["type"] = "hysteria2"
			hysteria2["server"] = urlHysteria2.Hostname()
			if port := urlHysteria2.Port(); port != "" {
				hysteria2["port"] = port
			} else {
				hysteria2["port"] = "443"
			}
			if ports != "" {
				hysteria2["ports"] = ports
			}
			hysteria2["obfs"] = query.Get("obfs")
			hysteria2["obfs-password"] = query.Get("obfs-password")
			hysteria2["sni"] = query.Get("sni")
			hysteria2["skip-cert-verify"], _ = strconv.ParseBool(query.Get("insecure"))
			if alpn := query.Get("alpn"); alpn != "" {
				hysteria2["alpn"] = strings.Split(alpn, ",")
			}
			hysteria2["fingerprint"] = query.Get("pinSHA256")
			hysteria2["down"] = query.Get("down")
			hysteria2["up"] = query.Get("up")
			if realmMode {
				token, _ := url.PathUnescape(urlHysteria2.User.String())
				realmID, _ := url.PathUnescape(strings.TrimPrefix(urlHysteria2.EscapedPath(), "/"))
				hysteria2["realm-opts"] = buildRealmOpts("https://"+urlHysteria2.Host, token, realmID, query["stun"])
				if auth := query.Get("auth"); auth != "" {
					hysteria2["password"] = auth
				}
			} else if auth := urlHysteria2.User.String(); auth != "" {
				hysteria2["password"] = auth
			}

			appendProxy(hysteria2, name, index)

		case "tuic":
			// A temporary unofficial TUIC share link standard
			// Modified from https://github.com/daeuniverse/dae/discussions/182
			// Changes:
			//   1. Support TUICv4, just replace uuid:password with token
			//   2. Remove `allow_insecure` field
			urlTUIC, err := url.Parse(line)
			if err != nil {
				continue
			}
			query := urlTUIC.Query()

			tuic := make(map[string]any, 20)
			tuic["type"] = scheme
			tuic["server"] = urlTUIC.Hostname()
			tuic["port"] = urlTUIC.Port()
			tuic["udp"] = true
			password, v5 := urlTUIC.User.Password()
			if v5 {
				tuic["uuid"] = urlTUIC.User.Username()
				tuic["password"] = password
			} else {
				tuic["token"] = urlTUIC.User.Username()
			}
			if cc := query.Get("congestion_control"); cc != "" {
				tuic["congestion-controller"] = cc
			}
			if alpn := query.Get("alpn"); alpn != "" {
				tuic["alpn"] = strings.Split(alpn, ",")
			}
			if sni := query.Get("sni"); sni != "" {
				tuic["sni"] = sni
			}
			if query.Get("disable_sni") == "1" {
				tuic["disable-sni"] = true
			}
			if udpRelayMode := query.Get("udp_relay_mode"); udpRelayMode != "" {
				tuic["udp-relay-mode"] = udpRelayMode
			}

			appendProxy(tuic, urlTUIC.Fragment, index)

		case "trojan":
			urlTrojan, err := url.Parse(line)
			if err != nil {
				continue
			}

			query := urlTrojan.Query()

			name := urlTrojan.Fragment
			trojan := make(map[string]any, 20)

			trojan["type"] = scheme
			trojan["server"] = urlTrojan.Hostname()
			trojan["port"] = urlTrojan.Port()
			trojan["password"] = urlTrojan.User.Username()
			trojan["udp"] = true
			trojan["skip-cert-verify"], _ = strconv.ParseBool(query.Get("allowInsecure"))

			if sni := query.Get("sni"); sni != "" {
				trojan["sni"] = sni
			}
			if alpn := query.Get("alpn"); alpn != "" {
				trojan["alpn"] = strings.Split(alpn, ",")
			}

			network := strings.ToLower(query.Get("type"))
			if network != "" {
				trojan["network"] = network
			}

			switch network {
			case "ws":
				headers := make(map[string]any)
				wsOpts := make(map[string]any)

				headers["User-Agent"] = RandUserAgent()

				wsOpts["path"] = query.Get("path")
				wsOpts["headers"] = headers

				trojan["ws-opts"] = wsOpts

			case "grpc":
				grpcOpts := make(map[string]any)
				grpcOpts["grpc-service-name"] = query.Get("serviceName")
				trojan["grpc-opts"] = grpcOpts
			}

			if fingerprint := query.Get("fp"); fingerprint == "" {
				trojan["client-fingerprint"] = "chrome"
			} else {
				trojan["client-fingerprint"] = fingerprint
			}

			if pcs := query.Get("pcs"); pcs != "" {
				trojan["fingerprint"] = pcs
			}

			appendProxy(trojan, name, index)

		case "vless":
			urlVLess, err := url.Parse(line)
			if err != nil {
				continue
			}
			if decodedHost, err := tryDecodeBase64([]byte(urlVLess.Host)); err == nil {
				urlVLess.Host = string(decodedHost)
			}
			query := urlVLess.Query()
			vless := make(map[string]any, 20)
			err = handleVShareLink(urlVLess, scheme, vless)
			if err != nil {
				log.Warnln("error:%s line:%s", err.Error(), line)
				continue
			}
			if flow := query.Get("flow"); flow != "" {
				vless["flow"] = strings.ToLower(flow)
			}
			if encryption := query.Get("encryption"); encryption != "" {
				vless["encryption"] = encryption
			}
			appendProxy(vless, urlVLess.Fragment, index)

		case "vmess":
			// V2RayN-styled share link
			// https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
			dcBuf, err := tryDecodeBase64([]byte(body))
			if err != nil {
				// Xray VMessAEAD share link
				urlVMess, err := url.Parse(line)
				if err != nil {
					continue
				}
				query := urlVMess.Query()
				vmess := make(map[string]any, 20)
				err = handleVShareLink(urlVMess, scheme, vmess)
				if err != nil {
					log.Warnln("error:%s line:%s", err.Error(), line)
					continue
				}
				vmess["alterId"] = 0
				vmess["cipher"] = "auto"
				if encryption := query.Get("encryption"); encryption != "" {
					vmess["cipher"] = encryption
				}
				appendProxy(vmess, urlVMess.Fragment, index)
				continue
			}

			jsonDc := json.NewDecoder(bytes.NewReader(dcBuf))
			values := make(map[string]any, 20)

			if jsonDc.Decode(&values) != nil {
				continue
			}
			tempName, ok := values["ps"].(string)
			if !ok {
				continue
			}
			name := tempName
			vmess := make(map[string]any, 20)

			vmess["type"] = scheme
			vmess["server"] = values["add"]
			vmess["port"] = values["port"]
			vmess["uuid"] = values["id"]
			if alterId, ok := values["aid"]; ok {
				vmess["alterId"] = alterId
			} else {
				vmess["alterId"] = 0
			}
			vmess["udp"] = true
			vmess["xudp"] = true
			vmess["tls"] = false
			vmess["skip-cert-verify"] = false

			vmess["cipher"] = "auto"
			if cipher, ok := values["scy"].(string); ok && cipher != "" {
				vmess["cipher"] = cipher
			}

			if sni, ok := values["sni"].(string); ok && sni != "" {
				vmess["servername"] = sni
			}

			network, ok := values["net"].(string)
			if ok {
				network = strings.ToLower(network)
				if values["type"] == "http" {
					network = "http"
				} else if network == "http" {
					network = "h2"
				}
				vmess["network"] = network
			}

			tls, ok := values["tls"].(string)
			if ok {
				tls = strings.ToLower(tls)
				if strings.HasSuffix(tls, "tls") {
					vmess["tls"] = true
				}
				if alpn, ok := values["alpn"].(string); ok {
					vmess["alpn"] = strings.Split(alpn, ",")
				}
			}

			switch network {
			case "http":
				headers := make(map[string]any)
				httpOpts := make(map[string]any)
				if host, ok := values["host"].(string); ok && host != "" {
					headers["Host"] = []string{host}
				}
				httpOpts["path"] = []string{"/"}
				if path, ok := values["path"].(string); ok && path != "" {
					httpOpts["path"] = []string{path}
				}
				httpOpts["headers"] = headers

				vmess["http-opts"] = httpOpts

			case "h2":
				h2Opts := make(map[string]any)
				h2Opts["path"] = "/"
				if path, ok := values["path"].(string); ok && path != "" {
					h2Opts["path"] = path
				}
				if host, ok := values["host"].(string); ok && host != "" {
					h2Opts["host"] = []string{host}
				}
				vmess["h2-opts"] = h2Opts

			case "ws", "httpupgrade":
				headers := make(map[string]any)
				wsOpts := make(map[string]any)
				wsOpts["path"] = "/"
				if host, ok := values["host"].(string); ok && host != "" {
					headers["Host"] = host
				}
				if path, ok := values["path"].(string); ok && path != "" {
					path := path
					pathURL, err := url.Parse(path)
					if err == nil {
						query := pathURL.Query()
						if earlyData := query.Get("ed"); earlyData != "" {
							med, err := strconv.Atoi(earlyData)
							if err == nil {
								switch network {
								case "ws":
									wsOpts["max-early-data"] = med
									wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
								case "httpupgrade":
									wsOpts["v2ray-http-upgrade-fast-open"] = true
								}
								query.Del("ed")
								pathURL.RawQuery = query.Encode()
								path = pathURL.String()
							}
						}
						if earlyDataHeader := query.Get("eh"); earlyDataHeader != "" {
							wsOpts["early-data-header-name"] = earlyDataHeader
						}
					}
					wsOpts["path"] = path
				}
				wsOpts["headers"] = headers
				vmess["ws-opts"] = wsOpts

			case "grpc":
				grpcOpts := make(map[string]any)
				grpcOpts["grpc-service-name"] = values["path"]
				vmess["grpc-opts"] = grpcOpts
			}

			appendProxy(vmess, name, index)

		case "ss":
			urlSS, err := url.Parse(line)
			if err != nil {
				continue
			}

			name := urlSS.Fragment
			port := urlSS.Port()

			if port == "" {
				dcBuf, err := encRaw.DecodeString(urlSS.Host)
				if err != nil {
					continue
				}

				urlSS, err = url.Parse("ss://" + string(dcBuf))
				if err != nil {
					continue
				}
			}

			var (
				cipherRaw = urlSS.User.Username()
				cipher    string
				password  string
			)
			cipher = cipherRaw
			if password, found = urlSS.User.Password(); !found {
				dcBuf, err := base64.RawURLEncoding.DecodeString(cipherRaw)
				if err != nil {
					dcBuf, _ = enc.DecodeString(cipherRaw)
				}
				cipher, password, found = strings.Cut(string(dcBuf), ":")
				if !found {
					continue
				}
				err = VerifyMethod(cipher, password)
				if err != nil {
					dcBuf, _ = encRaw.DecodeString(cipherRaw)
					cipher, password, found = strings.Cut(string(dcBuf), ":")
				}
			}

			ss := make(map[string]any, 10)

			ss["type"] = scheme
			ss["server"] = urlSS.Hostname()
			ss["port"] = urlSS.Port()
			ss["cipher"] = cipher
			ss["password"] = password
			query := urlSS.Query()
			ss["udp"] = true
			if query.Get("udp-over-tcp") == "true" || query.Get("uot") == "1" {
				ss["udp-over-tcp"] = true
			}
			plugin := query.Get("plugin")
			if strings.Contains(plugin, ";") {
				pluginInfo, _ := url.ParseQuery("pluginName=" + strings.ReplaceAll(plugin, ";", "&"))
				pluginName := pluginInfo.Get("pluginName")
				if strings.Contains(pluginName, "obfs") {
					ss["plugin"] = "obfs"
					ss["plugin-opts"] = map[string]any{
						"mode": pluginInfo.Get("obfs"),
						"host": pluginInfo.Get("obfs-host"),
					}
				} else if strings.Contains(pluginName, "v2ray-plugin") {
					mode := pluginInfo.Get("mode")
					if mode == "" {
						mode = pluginInfo.Get("obfs")
					}
					host := pluginInfo.Get("host")
					if host == "" {
						host = pluginInfo.Get("obfs-host")
					}
					ss["plugin"] = "v2ray-plugin"
					ss["plugin-opts"] = map[string]any{
						"mode": mode,
						"host": host,
						"path": pluginInfo.Get("path"),
						"tls":  strings.Contains(plugin, "tls"),
					}
				}
			}

			appendProxy(ss, name, index)

		case "ssr":
			dcBuf, err := TryDecodeBase64(body)
			if err != nil {
				continue
			}

			// ssr://host:port:protocol:method:obfs:urlsafebase64pass/?obfsparam=urlsafebase64param&protoparam=urlsafebase64param&remarks=urlsafebase64remarks&group=urlsafebase64group&udpport=0&uot=1

			before, after, ok := strings.Cut(string(dcBuf), "/?")
			if !ok {
				continue
			}

			beforeArr := strings.Split(before, ":")

			if len(beforeArr) != 6 {
				continue
			}

			host := beforeArr[0]
			port := beforeArr[1]
			protocol := beforeArr[2]
			method := beforeArr[3]
			obfs := beforeArr[4]
			password := decodeUrlSafe(urlSafe(beforeArr[5]))

			query, err := url.ParseQuery(urlSafe(after))
			if err != nil {
				continue
			}

			remarks := decodeUrlSafe(query.Get("remarks"))
			name := remarks

			obfsParam := decodeUrlSafe(query.Get("obfsparam"))
			protocolParam := decodeUrlSafe(query.Get("protoparam"))

			ssr := make(map[string]any, 20)

			ssr["type"] = scheme
			ssr["server"] = host
			ssr["port"] = port
			ssr["cipher"] = method
			ssr["password"] = password
			ssr["obfs"] = obfs
			ssr["protocol"] = protocol
			ssr["udp"] = true

			if obfsParam != "" {
				ssr["obfs-param"] = obfsParam
			}

			if protocolParam != "" {
				ssr["protocol-param"] = protocolParam
			}

			appendProxy(ssr, name, index)

		case "socks", "socks5", "socks5h", "http", "https":
			link, err := url.Parse(line)
			if err != nil {
				continue
			}
			server := link.Hostname()
			if server == "" {
				continue
			}
			portStr := link.Port()
			if portStr == "" {
				continue
			}
			remarks := link.Fragment
			if remarks == "" {
				remarks = fmt.Sprintf("%s:%s", server, portStr)
			}
			name := remarks
			encodeStr := link.User.String()
			var username, password string
			if encodeStr != "" {
				decodeStr := string(DecodeBase64([]byte(encodeStr)))
				splitStr := strings.Split(decodeStr, ":")

				// todo: should use url.QueryUnescape ?
				username = splitStr[0]
				if len(splitStr) == 2 {
					password = splitStr[1]
				}
			}
			socks := make(map[string]any, 10)
			socks["type"] = func() string {
				switch scheme {
				case "socks", "socks5", "socks5h":
					return "socks5"
				case "http", "https":
					return "http"
				}
				return scheme
			}()
			socks["server"] = server
			socks["port"] = portStr
			socks["username"] = username
			socks["password"] = password
			socks["skip-cert-verify"] = true
			if scheme == "https" {
				socks["tls"] = true
			}

			appendProxy(socks, name, index)

		case "anytls":
			// https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md
			link, err := url.Parse(line)
			if err != nil {
				continue
			}
			username := link.User.Username()
			password, exist := link.User.Password()
			if !exist {
				password = username
			}
			query := link.Query()
			server := link.Hostname()
			if server == "" {
				continue
			}
			portStr := link.Port()
			if portStr == "" {
				continue
			}
			insecure, sni := query.Get("insecure"), query.Get("sni")
			insecureBool := insecure == "1"
			fingerprint := query.Get("hpkp")

			remarks := link.Fragment
			if remarks == "" {
				remarks = fmt.Sprintf("%s:%s", server, portStr)
			}
			name := remarks
			anytls := make(map[string]any, 10)
			anytls["type"] = "anytls"
			anytls["server"] = server
			anytls["port"] = portStr
			anytls["username"] = username
			anytls["password"] = password
			anytls["sni"] = sni
			anytls["fingerprint"] = fingerprint
			anytls["skip-cert-verify"] = insecureBool
			anytls["udp"] = true

			appendProxy(anytls, name, index)

		case "mierus":
			urlMieru, err := url.Parse(line)
			if err != nil {
				continue
			}

			query := urlMieru.Query()

			server := urlMieru.Hostname()
			if server == "" {
				continue
			}
			username := urlMieru.User.Username()
			password, _ := urlMieru.User.Password()

			baseName := urlMieru.Fragment
			if baseName == "" {
				baseName = query.Get("profile")
			}
			if baseName == "" {
				baseName = server
			}

			multiplexing := query.Get("multiplexing")
			handshakeMode := query.Get("handshake-mode")
			trafficPattern := query.Get("traffic-pattern")

			portList := query["port"]
			protocolList := query["protocol"]
			if len(portList) == 0 || len(portList) != len(protocolList) {
				continue
			}

			for i, port := range portList {
				protocol := protocolList[i]
				name := fmt.Sprintf("%s:%s/%s", baseName, port, protocol)

				mieru := make(map[string]any, 15)
				mieru["type"] = "mieru"
				mieru["server"] = server
				mieru["transport"] = protocol
				mieru["udp"] = true
				mieru["username"] = username
				mieru["password"] = password

				if strings.Contains(port, "-") {
					mieru["port-range"] = port
				} else {
					portNum, err := strconv.Atoi(port)
					if err != nil {
						continue
					}
					mieru["port"] = portNum
				}

				if multiplexing != "" {
					mieru["multiplexing"] = multiplexing
				}
				if handshakeMode != "" {
					mieru["handshake-mode"] = handshakeMode
				}
				if trafficPattern != "" {
					mieru["traffic-pattern"] = trafficPattern
				}

				appendProxy(mieru, name, index)
			}
		}
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("convert v2ray subscribe error: format invalid")
	}

	return proxies, nil
}

// Validate only endpoint fields emitted by the converter. Leave credentials and
// transport options to adapters, after provider overrides have been applied.
func validateProxyEndpoint(proxy map[string]any) error {
	switch server := proxy["server"].(type) {
	case string:
		if strings.TrimSpace(server) == "" {
			return fmt.Errorf("empty server")
		}
	case float64: // Legacy VMess JSON: adapters also accept numeric scalars.
	default:
		return fmt.Errorf("invalid server")
	}

	if portRange, ok := proxy["port-range"].(string); ok {
		// Mieru represents an endpoint with either a single port or a range.
		beginText, endText, found := strings.Cut(portRange, "-")
		begin, beginErr := strconv.ParseUint(beginText, 10, 16)
		end, endErr := strconv.ParseUint(endText, 10, 16)
		if !found || beginErr != nil || endErr != nil || begin == 0 || begin > end {
			return fmt.Errorf("invalid port range")
		}
		return nil
	}

	var port int64
	switch value := proxy["port"].(type) {
	case string:
		var err error
		port, err = strconv.ParseInt(value, 0, strconv.IntSize)
		if err != nil {
			return fmt.Errorf("invalid port")
		}
	case float64: // Match the adapter's weak conversion of JSON numbers to int.
		if value < 1 || value >= 65536 {
			return fmt.Errorf("port must be between 1 and 65535")
		}
		port = int64(value)
	case int:
		port = int64(value)
	default:
		return fmt.Errorf("missing or invalid port")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	if ports, ok := proxy["ports"].(string); ok && ports != "" {
		// Hysteria2 narrows hopping ports to uint16; check bounds beforehand.
		ranges, err := utils.NewUnsignedRanges[uint64](ports)
		if err != nil {
			return fmt.Errorf("invalid hopping ports")
		}
		for _, ports := range ranges {
			if ports.Start() < 1 || ports.End() > 65535 {
				return fmt.Errorf("hopping ports must be between 1 and 65535")
			}
		}
	}
	return nil
}

func uniqueName(names map[string]int, name string) string {
	if index, ok := names[name]; ok {
		index++
		names[name] = index
		name = fmt.Sprintf("%s-%02d", name, index)
	} else {
		index = 0
		names[name] = index
	}
	return name
}
