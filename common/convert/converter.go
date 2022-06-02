package convert

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

var enc = base64.StdEncoding

func DecodeBase64(buf []byte) ([]byte, error) {
	dBuf := make([]byte, enc.DecodedLen(len(buf)))
	n, err := enc.Decode(dBuf, buf)
	if err != nil {
		return nil, err
	}

	return dBuf[:n], nil
}

// DecodeBase64StringToString decode base64 string to string
func DecodeBase64StringToString(s string) (string, error) {
	dBuf, err := enc.DecodeString(s)
	if err != nil {
		return "", err
	}

	return string(dBuf), nil
}

// ConvertsV2Ray convert V2Ray subscribe proxies data to clash proxies config
func ConvertsV2Ray(buf []byte) ([]map[string]any, error) {
	data, err := DecodeBase64(buf)
	if err != nil {
		data = buf
	}

	arr := strings.Split(string(data), "\n")

	proxies := make([]map[string]any, 0, len(arr))
	names := make(map[string]int, 200)

	for _, line := range arr {
		line = strings.TrimRight(line, " \r")
		if line == "" {
			continue
		}

		scheme, body, found := strings.Cut(line, "://")
		if !found {
			continue
		}

		scheme = strings.ToLower(scheme)
		switch scheme {
		case "trojan":
			urlTrojan, err := url.Parse(line)
			if err != nil {
				continue
			}

			q := urlTrojan.Query()

			name := uniqueName(names, urlTrojan.Fragment)
			trojan := make(map[string]any, 20)

			trojan["name"] = name
			trojan["type"] = scheme
			trojan["server"] = urlTrojan.Hostname()
			trojan["port"] = urlTrojan.Port()
			trojan["password"] = urlTrojan.User.Username()
			trojan["udp"] = true
			trojan["skip-cert-verify"] = false

			sni := q.Get("sni")
			if sni != "" {
				trojan["sni"] = sni
			}

			network := strings.ToLower(q.Get("type"))
			if network != "" {
				trojan["network"] = network
			}

			if network == "ws" {
				headers := make(map[string]any)
				wsOpts := make(map[string]any)

				headers["Host"] = RandHost()
				headers["User-Agent"] = RandUserAgent()

				wsOpts["path"] = q.Get("path")
				wsOpts["headers"] = headers

				trojan["ws-opts"] = wsOpts
			}

			proxies = append(proxies, trojan)
		case "vmess":
			dcBuf, err := enc.DecodeString(body)
			if err != nil {
				continue
			}

			jsonDc := json.NewDecoder(bytes.NewReader(dcBuf))
			values := make(map[string]any, 20)

			if jsonDc.Decode(&values) != nil {
				continue
			}

			name := uniqueName(names, values["ps"].(string))
			vmess := make(map[string]any, 20)

			vmess["name"] = name
			vmess["type"] = scheme
			vmess["server"] = values["add"]
			vmess["port"] = values["port"]
			vmess["uuid"] = values["id"]
			vmess["alterId"] = values["aid"]
			vmess["cipher"] = "auto"
			vmess["udp"] = true
			vmess["skip-cert-verify"] = false

			host := values["host"]
			network := strings.ToLower(values["net"].(string))

			vmess["network"] = network

			tls := strings.ToLower(values["tls"].(string))
			if tls != "" && tls != "0" && tls != "null" {
				if host != nil {
					vmess["servername"] = host
				}
				vmess["tls"] = true
			}

			if network == "ws" {
				headers := make(map[string]any)
				wsOpts := make(map[string]any)

				headers["Host"] = RandHost()
				headers["User-Agent"] = RandUserAgent()

				if values["path"] != nil {
					wsOpts["path"] = values["path"]
				}
				wsOpts["headers"] = headers

				vmess["ws-opts"] = wsOpts
			}

			proxies = append(proxies, vmess)
		case "ss":
			urlSS, err := url.Parse(line)
			if err != nil {
				continue
			}

			name := uniqueName(names, urlSS.Fragment)
			port := urlSS.Port()

			if port == "" {
				dcBuf, err := enc.DecodeString(urlSS.Host)
				if err != nil {
					continue
				}

				urlSS, err = url.Parse("ss://" + string(dcBuf))
				if err != nil {
					continue
				}
			}

			var (
				cipher   = urlSS.User.Username()
				password string
			)

			if password, found = urlSS.User.Password(); !found {
				dcBuf, err := enc.DecodeString(cipher)
				if err != nil {
					continue
				}

				cipher, password, found = strings.Cut(string(dcBuf), ":")
				if !found {
					continue
				}
			}

			ss := make(map[string]any, 20)

			ss["name"] = name
			ss["type"] = scheme
			ss["server"] = urlSS.Hostname()
			ss["port"] = urlSS.Port()
			ss["cipher"] = cipher
			ss["password"] = password
			ss["udp"] = true

			proxies = append(proxies, ss)
		case "ssr":
			dcBuf, err := enc.DecodeString(body)
			if err != nil {
				continue
			}

			// ssr://host:port:protocol:method:obfs:urlsafebase64pass/?obfsparam=urlsafebase64&protoparam=&remarks=urlsafebase64&group=urlsafebase64&udpport=0&uot=1

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
			name := uniqueName(names, remarks)

			obfsParam := decodeUrlSafe(query.Get("obfsparam"))
			protocolParam := query.Get("protoparam")

			ssr := make(map[string]any, 20)

			ssr["name"] = name
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

			proxies = append(proxies, ssr)
		case "vless":
			urlVless, err := url.Parse(line)
			if err != nil {
				continue
			}

			q := urlVless.Query()

			name := uniqueName(names, urlVless.Fragment)
			vless := make(map[string]any, 20)

			vless["name"] = name
			vless["type"] = scheme
			vless["server"] = urlVless.Hostname()
			vless["port"] = urlVless.Port()
			vless["uuid"] = urlVless.User.Username()
			vless["udp"] = true
			vless["skip-cert-verify"] = false

			sni := q.Get("sni")
			if sni != "" {
				vless["servername"] = sni
			}

			flow := strings.ToLower(q.Get("flow"))
			if flow != "" {
				vless["flow"] = flow
			}

			network := strings.ToLower(q.Get("type"))
			if network != "" {
				vless["network"] = network
			}

			if network == "ws" {
				headers := make(map[string]any)
				wsOpts := make(map[string]any)

				headers["Host"] = RandHost()
				headers["User-Agent"] = RandUserAgent()

				wsOpts["path"] = q.Get("path")
				wsOpts["headers"] = headers

				vless["ws-opts"] = wsOpts
			}

			proxies = append(proxies, vless)
		}
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("convert v2ray subscribe error: format invalid")
	}

	return proxies, nil
}

func urlSafe(data string) string {
	return strings.ReplaceAll(strings.ReplaceAll(data, "+", "-"), "/", "_")
}

func decodeUrlSafe(data string) string {
	dcBuf, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(dcBuf)
}

func uniqueName(names map[string]int, name string) string {
	if index, ok := names[name]; ok {
		index++
		names[name] = index
		name = name + "-" + fmt.Sprintf("%02d", index)
	} else {
		index = 0
		names[name] = index
	}
	return name
}
