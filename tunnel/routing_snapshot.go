package tunnel

import (
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Applied maps/slices are replaced, never modified in place. Holding their
// references keeps a connection's routing configuration alive across waits,
// without holding configMux or restarting a partially evaluated expression.
type routingSnapshot struct {
	rules     []C.Rule
	subRules  map[string][]C.Rule
	proxies   map[string]C.Proxy
	providers map[string]P.RuleProvider
}

func snapshotRouting() routingSnapshot {
	configMux.RLock()
	defer configMux.RUnlock()
	return routingSnapshot{rules: rules, subRules: subRules, proxies: proxies, providers: ruleProviders}
}
func (s routingSnapshot) helpers(metadata *C.Metadata, helper C.RuleMatchHelper) C.RuleMatchHelper {
	var strategies map[string]C.RuleSetMatcher
	helper.RuleSetLookup = func(name string) C.RuleSetMatcher {
		if matcher, ok := strategies[name]; ok {
			return matcher
		}
		p := s.providers[name]
		var matcher C.RuleSetMatcher
		if p != nil {
			matcher, _ = p.Strategy().(C.RuleSetMatcher)
			if matcher == nil {
				matcher = p
			}
		}
		if strategies == nil {
			strategies = make(map[string]C.RuleSetMatcher)
		}
		strategies[name] = matcher
		return matcher
	}
	helper.CheckPassRule = func(name string) bool {
		for p := s.proxies[name]; p != nil; p = p.Unwrap(metadata, false) {
			if p.Type() == C.PassRule {
				return true
			}
		}
		return false
	}
	return helper
}
