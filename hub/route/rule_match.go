package route

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/miekg/dns"
)

func matchRules(w http.ResponseWriter, r *http.Request) {
	metadata, supplied, resolve, ok := parseRuleMatchQuery(r)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	render.JSON(w, r, tunnel.MatchRules(r.Context(), metadata, supplied, resolve))
}

func parseRuleMatchQuery(r *http.Request) (m C.Metadata, supplied map[string]bool, resolve bool, valid bool) {
	m = C.Metadata{NetWork: C.TCP}
	supplied = make(map[string]bool)
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return m, supplied, resolve, false
	}
	for key, values := range q {
		if len(values) != 1 || values[0] == "" {
			return m, supplied, resolve, false
		}
		value := values[0]
		switch key {
		case "resolve":
			if value != "true" && value != "false" {
				return m, supplied, resolve, false
			}
			resolve = value == "true"
			continue
		case "domain":
			m.Host = strings.TrimSuffix(strings.ToLower(value), ".")
			if _, valid := dns.IsDomainName(dns.Fqdn(m.Host)); !valid || m.Host == "" || strings.ContainsAny(m.Host, " /\\:@?#*+\t\r\n") {
				return m, supplied, resolve, false
			}
			if _, err := netip.ParseAddr(m.Host); err == nil {
				return m, supplied, resolve, false
			}
		case "ip", "source-ip":
			ip, err := netip.ParseAddr(value)
			if err != nil || ip.Zone() != "" {
				return m, supplied, resolve, false
			}
			if key == "ip" {
				m.DstIP = ip.Unmap()
			} else {
				m.SrcIP = ip.Unmap()
			}
		case "port", "source-port":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				return m, supplied, resolve, false
			}
			if key == "port" {
				m.DstPort = uint16(port)
			} else {
				m.SrcPort = uint16(port)
			}
		case "network":
			switch value {
			case "tcp":
				m.NetWork = C.TCP
			case "udp":
				m.NetWork = C.UDP
			default:
				return m, supplied, resolve, false
			}
		case "process":
			m.Process = value
		case "process-path":
			m.ProcessPath = value
		case "inbound":
			m.InName = value
		case "uid":
			uid, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return m, supplied, resolve, false
			}
			m.Uid = uint32(uid)
		default:
			return m, supplied, resolve, false
		}
		supplied[key] = true
	}
	return m, supplied, resolve, m.Host != "" || m.DstIP.IsValid()
}
