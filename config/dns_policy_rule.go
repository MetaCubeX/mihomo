package config

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/common/lru"
	C "github.com/metacubex/mihomo/constant"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/mihomo/tunnel"
)

var cache = lru.New[string, C.AdapterType](
	lru.WithAge[string, C.AdapterType](1),
)

type ruleMatcher struct {
	typ string
}

func (r *ruleMatcher) MatchDomain(domain string) bool {
	typ, found := cache.Get(domain)
	if !found {
		p, _, err := tunnel.ResolveMetadata(
			&C.Metadata{
				NetWork: C.TCP,
				Type:    C.INNER, // avoid process lookup
				Host:    domain,
				DstIP:   netip.AddrFrom4([4]byte{}), // avoid dns lookup
			},
		)
		if err != nil {
			log.Warnln("[DNS] ruleMatcher: match(%s) got err %v", domain, err.Error())
			return false
		}
		log.Debugln("[DNS] ruleMatcher: match(%s) -> %s", domain, p.Type().String())
		cache.Set(domain, p.Type())
		typ = p.Type()
	}
	switch typ {
	case C.Direct, C.Compatible:
		if r.typ == "direct" {
			return true
		}
	case C.Reject, C.RejectDrop:
		if r.typ == "reject" {
			return true
		}
	case C.Pass: // should not happen
	default:
		if r.typ == "proxy" {
			return true
		}
	}
	return false
}

func newRuleMatcher(value string, _ map[string]providerTypes.RuleProvider) (C.DomainMatcher, error) {
	switch strings.ToLower(value) {
	case "direct":
		return &ruleMatcher{typ: "direct"}, nil
	case "reject":
		return &ruleMatcher{typ: "reject"}, nil
	case "proxy":
		return &ruleMatcher{typ: "proxy"}, nil
	default:
		return nil, errors.New("[DNS] rulePolicy: unknown rule type: " + value)
	}
}
