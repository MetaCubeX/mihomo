package tunnel

import (
	"context"
	"slices"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

// RuleMatchResult describes evaluation of configured rules, independent of mode.
// An incomplete result deliberately has no policy: absent metadata might change the winner.
type RuleMatchResult struct {
	Mode     string              `json:"mode"`
	Complete bool                `json:"complete"`
	Network  string              `json:"network"`
	Missing  []string            `json:"missing"`
	IP       string              `json:"ip,omitempty"`
	DNS      RuleMatchDNS        `json:"dns"`
	Rule     *RuleMatchLocation  `json:"rule"`
	SubRules []RuleMatchLocation `json:"subRules,omitempty"`
	Policy   string              `json:"policy,omitempty"`
}

// Attempted reports a lazy resolver invocation, which may use hosts or DNS cache
// instead of sending an upstream query. Error is set only when that lookup fails.
type RuleMatchDNS struct {
	Enabled   bool   `json:"enabled"`
	Attempted bool   `json:"attempted"`
	Error     string `json:"error,omitempty"`
}

type RuleMatchLocation struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Name    string `json:"name,omitempty"`
}

// MatchRules evaluates rules without opening a business connection, looking up a
// process, or recording statistics. DNS is disabled unless resolve is true, and
// then runs only when a rule requests it. supplied identifies optional metadata
// explicitly provided by the caller (notably UID zero and network).
func MatchRules(ctx context.Context, metadata C.Metadata, supplied map[string]bool, resolve bool) RuleMatchResult {
	// Do not hold configMux while resolving: DNS respect-rules may reenter the
	// matcher, deadlocking a recursive RLock when a config writer is pending.
	configMux.RLock()
	config := ruleMatchConfig{rules: rules, subRules: subRules, proxies: proxies}
	providers := ruleProviders
	configMux.RUnlock()
	result := RuleMatchResult{Mode: "rule", Complete: true, Missing: []string{}, DNS: RuleMatchDNS{Enabled: resolve}}
	result.Network = metadata.NetWork.String()
	missing := func(field string, available bool) bool {
		if available {
			return true
		}
		if !slices.Contains(result.Missing, field) {
			result.Missing = append(result.Missing, field)
		}
		result.Complete = false
		return false
	}
	helper := C.RuleMatchHelper{
		Diagnostics: &C.RuleMatchDiagnostics{
			Incomplete: func() bool { return !result.Complete },
			BeginRule:  func() { result.SubRules = nil },
			MatchProvider: func(name string, m *C.Metadata, helper C.RuleMatchHelper) bool {
				provider := providers[name]
				if provider == nil {
					return false
				}
				behavior := provider.Behavior()
				if behavior == P.Domain && !missing("domain", m.Host != "") {
					return false
				}
				matched := provider.Match(m, helper)
				// The actual IP strategy decides whether to resolve, including in source mode.
				if behavior == P.IPCIDR && !missing(helper.Diagnostics.OriginalField("ip"), m.DstIP.IsValid()) {
					return false
				}
				return matched
			},
			BeforeMatch: func(rule C.Rule, m *C.Metadata, diagnostics *C.RuleMatchDiagnostics) bool {
				switch rule.RuleType() {
				case C.Domain, C.DomainSuffix, C.DomainKeyword, C.DomainRegex, C.DomainWildcard, C.GEOSITE:
					return missing("domain", m.Host != "")
				case C.DstPort:
					return missing(diagnostics.OriginalField("port"), supplied[diagnostics.OriginalField("port")])
				case C.SrcPort:
					return missing(diagnostics.OriginalField("source-port"), supplied[diagnostics.OriginalField("source-port")])
				case C.Network:
					return missing("network", supplied["network"])
				case C.ProcessName, C.ProcessNameRegex, C.ProcessNameWildcard:
					return missing("process", m.Process != "")
				case C.ProcessPath, C.ProcessPathRegex, C.ProcessPathWildcard:
					return missing("process-path", m.ProcessPath != "")
				case C.Uid:
					return missing("uid", supplied["uid"])
				case C.InName:
					return missing("inbound", m.InName != "")
				case C.InType:
					return missing("inbound-type", false)
				case C.InPort:
					return missing("inbound-port", false)
				case C.InUser:
					return missing("inbound-user", false)
				case C.DSCP:
					return missing("dscp", false)
				}
				return true
			},
			// Let the actual leaf invoke ResolveIP first, so no-resolve and
			// source-mode rules retain authority over whether DNS is permitted.
			AfterMatch: func(rule C.Rule, m *C.Metadata, diagnostics *C.RuleMatchDiagnostics) bool {
				switch rule.RuleType() {
				case C.GEOIP, C.IPASN, C.IPCIDR, C.IPSuffix:
					return missing(diagnostics.OriginalField("ip"), m.DstIP.IsValid())
				case C.SrcGEOIP, C.SrcIPASN, C.SrcIPCIDR, C.SrcIPSuffix:
					return missing(diagnostics.OriginalField("source-ip"), m.SrcIP.IsValid())
				}
				return true
			},
			SubRuleMatched: func(name string, index int, rule C.Rule) {
				result.SubRules = append(result.SubRules, RuleMatchLocation{Index: index, Type: rule.RuleType().String(), Payload: rule.Payload(), Name: name})
			},
		},
		CheckPassRule: func(name string) bool {
			for adapter := config.proxies[name]; adapter != nil; adapter = unwrapRuleProxy(adapter, &metadata, true) {
				if adapter.Type() == C.PassRule {
					return true
				}
			}
			return false
		},
	}
	if resolve {
		resolved := false
		helper.ResolveIP = func() {
			attempted, err := resolveRuleIP(ctx, &metadata, &resolved)
			result.DNS.Attempted = result.DNS.Attempted || attempted
			if err != nil {
				result.DNS.Error = err.Error()
				missing("ip", false)
			}
		}
	}
	proxy, rule, _ := matchWithConfig(&metadata, helper, &config)
	if metadata.DstIP.IsValid() {
		result.IP = metadata.DstIP.String()
	}
	if rule != nil {
		for index, candidate := range config.getRules(&metadata) {
			if candidate == rule {
				result.Rule = &RuleMatchLocation{Index: index, Type: rule.RuleType().String(), Payload: rule.Payload(), Name: metadata.SpecialRules}
				break
			}
		}
	}
	if result.Complete && proxy != nil {
		result.Policy = proxy.Name()
	}
	return result
}

// resolveRuleIP is the lazy DNS operation shared by live and diagnostic rule
// matching. The rule decides whether to call it; an existing IP is never replaced.
func resolveRuleIP(ctx context.Context, metadata *C.Metadata, resolved *bool) (attempted bool, err error) {
	if *resolved || metadata.Host == "" || metadata.Resolved() {
		return false, nil
	}
	*resolved = true
	ctx, cancel := context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return true, err
	}
	ip, err := resolver.ResolveIP(ctx, metadata.Host)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
	} else {
		log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
		metadata.DstIP = ip
	}
	return true, err
}

func unwrapRuleProxy(proxy C.Proxy, metadata *C.Metadata, diagnostic bool) C.Proxy {
	if diagnostic {
		if readOnly, ok := proxy.Adapter().(interface {
			UnwrapReadOnly(*C.Metadata) C.Proxy
		}); ok {
			return readOnly.UnwrapReadOnly(metadata)
		}
	}
	return proxy.Unwrap(metadata, false)
}
