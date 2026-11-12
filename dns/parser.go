package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/exp/slices"
)

// ParseNameServer parses nameservers with rule routing and HTTP/3 preference disabled.
func ParseNameServer(servers []string) ([]NameServer, error) {
	return ParseNameServerWithOptions(servers, false, false)
}

// ParseNameServerWithOptions parses nameservers with the given DNS options.
// respectRules applies rule routing when no proxy is specified; preferH3 sets
// the HTTP/3 preference on the resulting nameservers.
func ParseNameServerWithOptions(servers []string, respectRules bool, preferH3 bool) ([]NameServer, error) {
	var nameservers []NameServer

	for idx, server := range servers {
		server = parsePureDNSServer(server)
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		var proxyName string
		params := map[string]string{}
		for _, s := range strings.Split(u.Fragment, "&") {
			arr := strings.SplitN(s, "=", 2)
			switch len(arr) {
			case 1:
				proxyName = arr[0]
			case 2:
				params[arr[0]] = arr[1]
			}
		}

		var addr, dnsNetType string
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "" // UDP
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp" // TCP
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tls" // DNS over TLS
		case "http", "https":
			addr, err = hostWithDefaultPort(u.Host, "443")
			dnsNetType = "https" // DNS over HTTPS
			if u.Scheme == "http" {
				addr, err = hostWithDefaultPort(u.Host, "80")
			}
			if err == nil {
				clearURL := url.URL{Scheme: u.Scheme, Host: addr, Path: u.Path, User: u.User}
				addr = clearURL.String()
			}
		case "quic":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "quic" // DNS over QUIC
		case "system":
			dnsNetType = "system" // System DNS
		case "ts", "tailscale":
			addr = u.Host
			dnsNetType = "tailscale" // Tailscale DNS via proxy name
			if addr == "" {
				err = errors.New("missing Tailscale proxy name")
			}
		case "et", "easytier":
			addr = u.Host
			dnsNetType = "easytier" // EasyTier overlay DNS via proxy name
			if addr == "" {
				err = errors.New("missing EasyTier proxy name")
			}
		case "dhcp":
			addr = server[len("dhcp://"):] // some special notation cannot be parsed by url
			dnsNetType = "dhcp"            // UDP from DHCP
			if addr == "system" {          // Compatible with old writing "dhcp://system"
				dnsNetType = "system"
				addr = ""
			}
		case "rcode":
			dnsNetType = "rcode"
			addr = u.Host
			switch addr {
			case "success",
				"format_error",
				"server_failure",
				"name_error",
				"not_implemented",
				"refused":
			default:
				err = fmt.Errorf("unsupported RCode type: %s", addr)
			}
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		if respectRules && len(proxyName) == 0 {
			proxyName = RespectRules
		}

		nameserver := NameServer{
			Net:       dnsNetType,
			Addr:      addr,
			ProxyName: proxyName,
			Params:    params,
			PreferH3:  preferH3,
		}
		if slices.ContainsFunc(nameservers, nameserver.Equal) {
			continue // skip duplicates nameserver
		}

		nameservers = append(nameservers, nameserver)
	}
	return nameservers, nil
}

func hostWithDefaultPort(host string, defPort string) (string, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", err
		}
		host = host + ":" + defPort
		if hostname, port, err = net.SplitHostPort(host); err != nil {
			return "", err
		}
	}

	return net.JoinHostPort(hostname, port), nil
}

func parsePureDNSServer(server string) string {
	addPre := func(server string) string {
		return "udp://" + server
	}

	if server == "system" {
		return "system://"
	}

	if ip, err := netip.ParseAddr(server); err != nil {
		if strings.Contains(server, "://") {
			return server
		}
		return addPre(server)
	} else {
		if ip.Is4() {
			return addPre(server)
		} else {
			return addPre("[" + server + "]")
		}
	}
}
