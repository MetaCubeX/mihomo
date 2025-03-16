package config

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/dns"
	RC "github.com/metacubex/mihomo/rules/common"
)

type matcher func(value string, ruleProviders map[string]providerTypes.RuleProvider) (C.DomainMatcher, error)

var policyMatcherMap = map[string]matcher{
	"rule-set": func(value string, ruleProviders map[string]providerTypes.RuleProvider) (C.DomainMatcher, error) {
		return parseDomainRuleSet(value, "dns.nameserver-policy", ruleProviders)
	},
	"geosite": func(value string, _ map[string]providerTypes.RuleProvider) (C.DomainMatcher, error) {
		return RC.NewGEOSITE(value, "dns.nameserver-policy")
	},
	"rule": newRuleMatcher,
}

func getMatcher(k string) (string, matcher) {
	typ, v, found := strings.Cut(k, ":")
	if !found {
		return k, nil
	}
	matcher := policyMatcherMap[strings.ToLower(typ)]
	// unknown, keep as original
	if matcher == nil {
		return k, nil
	}
	return v, matcher
}

func parseDNSPolicy(k string, nameservers []dns.NameServer,
	ruleProviders map[string]providerTypes.RuleProvider,
) ([]dns.Policy, error) {
	var policy []dns.Policy

	v, matcher := getMatcher(k)
	for _, subkey := range strings.Split(v, ",") {
		if matcher != nil {
			m, err := matcher(subkey, ruleProviders)
			if err != nil {
				return nil, err
			}
			policy = append(policy, dns.Policy{Matcher: m, NameServers: nameservers})
		} else {
			if _, valid := trie.ValidAndSplitDomain(subkey); !valid {
				return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", subkey)
			}
			policy = append(policy, dns.Policy{Domain: subkey, NameServers: nameservers})
		}
	}
	return policy, nil
}
