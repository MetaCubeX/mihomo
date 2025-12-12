package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/picker"
	"github.com/metacubex/mihomo/component/ech/echparser"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

const (
	MaxMsgSize = 65535
)

const serverFailureCacheTTL uint32 = 5

func minimalTTL(records []D.RR) uint32 {
	rr := lo.MinBy(records, func(r1 D.RR, r2 D.RR) bool {
		return r1.Header().Ttl < r2.Header().Ttl
	})
	if rr == nil {
		return 0
	}
	return rr.Header().Ttl
}

func updateTTL(records []D.RR, ttl uint32) {
	if len(records) == 0 {
		return
	}
	delta := minimalTTL(records) - ttl
	for i := range records {
		records[i].Header().Ttl = lo.Clamp(records[i].Header().Ttl-delta, 1, records[i].Header().Ttl)
	}
}

func putMsgToCache(c dnsCache, key string, q D.Question, msg *D.Msg) {
	// skip dns cache for acme challenge
	if q.Qtype == D.TypeTXT && strings.HasPrefix(q.Name, "_acme-challenge.") {
		log.Debugln("[DNS] dns cache ignored because of acme challenge for: %s", q.Name)
		return
	}

	var ttl uint32
	if msg.Rcode == D.RcodeServerFailure {
		// [...] a resolver MAY cache a server failure response.
		// If it does so it MUST NOT cache it for longer than five (5) minutes [...]
		ttl = serverFailureCacheTTL
	} else {
		ttl = minimalTTL(append(append(msg.Answer, msg.Ns...), msg.Extra...))
	}
	if ttl == 0 {
		return
	}
	c.SetWithExpire(key, msg.Copy(), time.Now().Add(time.Duration(ttl)*time.Second))
}

func setMsgTTL(msg *D.Msg, ttl uint32) {
	for _, answer := range msg.Answer {
		answer.Header().Ttl = ttl
	}

	for _, ns := range msg.Ns {
		ns.Header().Ttl = ttl
	}

	for _, extra := range msg.Extra {
		extra.Header().Ttl = ttl
	}
}

func updateMsgTTL(msg *D.Msg, ttl uint32) {
	updateTTL(msg.Answer, ttl)
	updateTTL(msg.Ns, ttl)
	updateTTL(msg.Extra, ttl)
}

func isIPRequest(q D.Question) bool {
	return q.Qclass == D.ClassINET && (q.Qtype == D.TypeA || q.Qtype == D.TypeAAAA || q.Qtype == D.TypeCNAME)
}

func transform(servers []NameServer, resolver *Resolver) []dnsClient {
	ret := make([]dnsClient, 0, len(servers))
	for _, s := range servers {
		var c dnsClient
		switch s.Net {
		case "https":
			c = newDoHClient(s.Addr, resolver, s.PreferH3, s.Params, s.ProxyAdapter, s.ProxyName)
		case "dhcp":
			c = newDHCPClient(s.Addr)
		case "system":
			c = newSystemClient()
		case "rcode":
			c = newRCodeClient(s.Addr)
		case "quic":
			c = newDoQ(s.Addr, resolver, s.Params, s.ProxyAdapter, s.ProxyName)
		default:
			c = newClient(s.Addr, resolver, s.Net, s.Params, s.ProxyAdapter, s.ProxyName)
		}

		c = warpClientWithEdns0Subnet(c, s.Params)

		if s.Params["disable-ipv4"] == "true" {
			c = warpClientWithDisableType(c, D.TypeA)
		}

		if s.Params["disable-ipv6"] == "true" {
			c = warpClientWithDisableType(c, D.TypeAAAA)
		}

		ret = append(ret, c)
	}
	return ret
}

type clientWithDisableType struct {
	dnsClient
	qType uint16
}

func (c clientWithDisableType) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if len(m.Question) > 0 {
		q := m.Question[0]
		if q.Qtype == c.qType {
			return handleMsgWithEmptyAnswer(m), nil
		}
	}
	return c.dnsClient.ExchangeContext(ctx, m)
}

func warpClientWithDisableType(c dnsClient, qType uint16) dnsClient {
	return clientWithDisableType{c, qType}
}

type clientWithEdns0Subnet struct {
	dnsClient
	ecsPrefix   netip.Prefix
	ecsOverride bool
}

func (c clientWithEdns0Subnet) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	m = m.Copy()
	setEdns0Subnet(m, c.ecsPrefix, c.ecsOverride)
	return c.dnsClient.ExchangeContext(ctx, m)
}

func warpClientWithEdns0Subnet(c dnsClient, params map[string]string) dnsClient {
	var ecsPrefix netip.Prefix
	var ecsOverride bool
	if ecs := params["ecs"]; ecs != "" {
		prefix, err := netip.ParsePrefix(ecs)
		if err != nil {
			addr, err := netip.ParseAddr(ecs)
			if err != nil {
				log.Warnln("DNS [%s] config with invalid ecs: %s", c.Address(), ecs)
			} else {
				ecsPrefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		} else {
			ecsPrefix = prefix
		}
	}

	if ecsPrefix.IsValid() {
		log.Debugln("DNS [%s] config with ecs: %s", c.Address(), ecsPrefix)
		if params["ecs-override"] == "true" {
			ecsOverride = true
		}
		return clientWithEdns0Subnet{c, ecsPrefix, ecsOverride}
	}
	return c
}

func handleMsgWithEmptyAnswer(r *D.Msg) *D.Msg {
	msg := &D.Msg{}
	msg.Answer = []D.RR{}

	msg.SetRcode(r, D.RcodeSuccess)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	return msg
}

func msgToIP(msg *D.Msg) (ips []netip.Addr) {
	for _, answer := range msg.Answer {
		var ip netip.Addr
		switch ans := answer.(type) {
		case *D.AAAA:
			ip, _ = netip.AddrFromSlice(ans.AAAA)
		case *D.A:
			ip, _ = netip.AddrFromSlice(ans.A)
		default:
			continue
		}
		if !ip.IsValid() {
			continue
		}
		ip = ip.Unmap()
		ips = append(ips, ip)
	}
	return
}

func msgToDomain(msg *D.Msg) string {
	if len(msg.Question) > 0 {
		return strings.TrimRight(msg.Question[0].Name, ".")
	}

	return ""
}

func msgToQtype(msg *D.Msg) (uint16, string) {
	if len(msg.Question) > 0 {
		qType := msg.Question[0].Qtype
		return qType, D.Type(qType).String()
	}
	return 0, ""
}

func msgToHTTPSRRInfo(msg *D.Msg) string {
	var alpns []string
	var publicName string
	var hasIPv4, hasIPv6 bool

	collect := func(rrs []D.RR) {
		for _, rr := range rrs {
			httpsRR, ok := rr.(*D.HTTPS)
			if !ok {
				continue
			}

			for _, kv := range httpsRR.Value {
				switch v := kv.(type) {
				case *D.SVCBAlpn:
					if len(alpns) == 0 && len(v.Alpn) > 0 {
						alpns = append(alpns, v.Alpn...)
					}
				case *D.SVCBIPv4Hint:
					if len(v.Hint) > 0 {
						hasIPv4 = true
					}
				case *D.SVCBIPv6Hint:
					if len(v.Hint) > 0 {
						hasIPv6 = true
					}
				case *D.SVCBECHConfig:
					if publicName == "" && len(v.ECH) > 0 {
						if cfgs, err := echparser.ParseECHConfigList(v.ECH); err == nil && len(cfgs) > 0 {
							publicName = string(cfgs[0].PublicName)
						}
					}
				}
			}
		}
	}

	collect(msg.Answer)
	collect(msg.Extra)

	if len(alpns) == 0 && publicName == "" && !hasIPv4 && !hasIPv6 {
		return ""
	}

	var parts []string
	if len(alpns) > 0 {
		parts = append(parts, "alpn:"+strings.Join(alpns, ","))
	}
	if publicName != "" {
		parts = append(parts, "pn:"+publicName)
	}
	if hasIPv4 {
		parts = append(parts, "ipv4hint")
	}
	if hasIPv6 {
		parts = append(parts, "ipv6hint")
	}

	return strings.Join(parts, ";")
}

func msgToLogString(msg *D.Msg) string {
	qType, qTypeStr := msgToQtype(msg)
	switch qType {
	case D.TypeHTTPS:
		return fmt.Sprintf("[%s] %s", msgToHTTPSRRInfo(msg), qTypeStr)
	default:
		return fmt.Sprintf("%s %s", msgToIP(msg), qTypeStr)
	}
}

func batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *D.Msg, cache bool, err error) {
	cache = true
	fast, ctx := picker.WithTimeout[*D.Msg](ctx, resolver.DefaultDNSTimeout)
	defer fast.Close()
	domain := msgToDomain(m)
	_, qTypeStr := msgToQtype(m)
	for _, client := range clients {
		if _, isRCodeClient := client.(rcodeClient); isRCodeClient {
			msg, err = client.ExchangeContext(ctx, m)
			return msg, false, err
		}
		client := client // shadow define client to ensure the value captured by the closure will not be changed in the next loop
		fast.Go(func() (*D.Msg, error) {
			log.Debugln("[DNS] resolve %s %s from %s", domain, qTypeStr, client.Address())
			m, err := client.ExchangeContext(ctx, m)
			if err != nil {
				return nil, err
			} else if cache && (m.Rcode == D.RcodeServerFailure || m.Rcode == D.RcodeRefused) {
				// currently, cache indicates whether this msg was from a RCode client,
				// so we would ignore RCode errors from RCode clients.
				return nil, errors.New("server failure: " + D.RcodeToString[m.Rcode])
			}
			log.Debugln("[DNS] %s --> %s from %s", domain, msgToLogString(m), client.Address())
			return m, nil
		})
	}

	msg = fast.Wait()
	if msg == nil {
		err = errors.New("all DNS requests failed")
		if fErr := fast.Error(); fErr != nil {
			err = fmt.Errorf("%w, first error: %w", err, fErr)
		}
	}
	return
}
