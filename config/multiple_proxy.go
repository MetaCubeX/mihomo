package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/wildcard"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/listener"
	RC "github.com/metacubex/mihomo/rules/common"
	T "github.com/metacubex/mihomo/tunnel"

	"golang.org/x/exp/slices"
)

// multipleProxyReservedNames are the built-in proxies that must never be
// matched as nodes when synthesizing a matchs group.
var multipleProxyReservedNames = map[string]struct{}{
	"DIRECT":      {},
	"REJECT":      {},
	"REJECT-DROP": {},
	"COMPATIBLE":  {},
	"PASS":        {},
	"PASS-RULE":   {},
	"GLOBAL":      {},
}

// multipleProxyGroupTypes are the proxy group types a matchs entry may use.
var multipleProxyGroupTypes = map[string]struct{}{
	"select":       {},
	"url-test":     {},
	"fallback":     {},
	"load-balance": {},
}

// multipleProxyEntryPrefix renders an identifying prefix for error messages.
// The name is optional, so fall back to the entry's ports when it is absent.
func multipleProxyEntryPrefix(entry RawMultipleProxy) string {
	if entry.Name != "" {
		return fmt.Sprintf("multiple-proxy %s", entry.Name)
	}
	return fmt.Sprintf("multiple-proxy (mixed-port=%d, port=%d, socks-port=%d)", entry.MixedPort, entry.Port, entry.SocksPort)
}

// multipleProxyListenerType returns the inbound listener type and port for a
// multiple-proxy entry. Exactly one of MixedPort/Port/SocksPort must be set.
func multipleProxyListenerType(entry RawMultipleProxy) (ltype string, port int, err error) {
	count := 0
	for _, p := range []int{entry.MixedPort, entry.Port, entry.SocksPort} {
		if p != 0 {
			count++
		}
	}
	if count != 1 {
		return "", 0, fmt.Errorf("%s: exactly one of mixed-port, port, socks-port must be set", multipleProxyEntryPrefix(entry))
	}

	switch {
	case entry.MixedPort != 0:
		return "mixed", entry.MixedPort, nil
	case entry.Port != 0:
		return "http", entry.Port, nil
	default:
		return "socks", entry.SocksPort, nil
	}
}

// validateMultipleProxyMode checks a multiple-proxy mode. An empty mode is
// allowed and means the global mode is inherited. The lookup is
// case-insensitive, matching the global mode handling in TunnelMode.UnmarshalText.
func validateMultipleProxyMode(mode string) error {
	if mode == "" {
		return nil
	}
	if _, exist := T.ModeMapping[strings.ToLower(mode)]; !exist {
		return fmt.Errorf("invalid multiple-proxy mode: %s", mode)
	}
	return nil
}

// listenerPortString normalizes a raw listener "port" value to the string form
// expected by utils.NewUnsignedRanges. YAML decodes a quoted range (e.g.
// "8000-8002") as a string but an unquoted single port (e.g. 10808) as an int.
func listenerPortString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	default:
		return "", false
	}
}

// collectUsedPorts returns every port occupied by the raw config, mapped to a
// human readable owner description. Ports of multiple-proxy entries are not
// included here; callers check them separately against this set.
func collectUsedPorts(cfg *RawConfig) (map[uint16]string, error) {
	used := make(map[uint16]string)

	scalars := []struct {
		port  int
		owner string
	}{
		{cfg.MixedPort, "mixed-port"},
		{cfg.Port, "port"},
		{cfg.SocksPort, "socks-port"},
		{cfg.RedirPort, "redir-port"},
		{cfg.TProxyPort, "tproxy-port"},
	}
	for _, scalar := range scalars {
		if scalar.port != 0 {
			used[uint16(scalar.port)] = scalar.owner
		}
	}

	for i, mapping := range cfg.Listeners {
		rawPort, exist := mapping["port"]
		if !exist {
			continue
		}
		portStr, ok := listenerPortString(rawPort)
		if !ok {
			continue
		}
		ports, err := utils.NewUnsignedRanges[uint16](portStr)
		if err != nil {
			return nil, fmt.Errorf("listener %d: %w", i, err)
		}
		owner := fmt.Sprintf("listener %d", i)
		if name, ok := mapping["name"].(string); ok && name != "" {
			owner = fmt.Sprintf("listener %s", name)
		}
		ports.Range(func(port uint16) bool {
			used[port] = owner
			return true
		})
	}

	return used, nil
}

// multipleProxyID returns a stable identifier for a multiple-proxy entry.
func multipleProxyID(entry RawMultipleProxy, idx int) string {
	if entry.Name != "" {
		return entry.Name
	}
	return fmt.Sprintf("multiple-proxy-%d", idx)
}

// isMatchableProxy reports whether a proxy may be used as a node of a
// synthesized matchs group. Reserved built-in names and existing proxy groups
// are never matchable.
func isMatchableProxy(name string, p C.Proxy) bool {
	if _, reserved := multipleProxyReservedNames[name]; reserved {
		return false
	}
	if _, isGroup := p.Adapter().(outboundgroup.ProxyGroup); isGroup {
		return false
	}
	return true
}

// buildMatchsGroup synthesizes a proxy group from the nodes matched by the
// name patterns of a multiple-proxy entry. Each entry name may contain `|`
// separated alternatives. The resulting group is registered into proxies and
// providersMap.
func buildMatchsGroup(groupName string, entries []RawMatchsEntry, proxies map[string]C.Proxy, providersMap map[string]P.ProxyProvider) (C.Proxy, error) {
	// The type is resolved per entry (omitted means "select") and every entry
	// must agree, so a bare pattern can not silently inherit another entry's
	// type. default-selected follows the same uniform rule.
	groupType := ""
	defaultSelected := ""
	for _, entry := range entries {
		effectiveType := entry.Type
		if effectiveType == "" {
			effectiveType = "select"
		}
		if groupType == "" {
			groupType = effectiveType
		} else if effectiveType != groupType {
			return nil, fmt.Errorf("multiple-proxy: matchs for %q have inconsistent types: %s and %s", groupName, groupType, effectiveType)
		}

		if entry.DefaultSelected != "" {
			if defaultSelected == "" {
				defaultSelected = entry.DefaultSelected
			} else if entry.DefaultSelected != defaultSelected {
				return nil, fmt.Errorf("multiple-proxy: matchs for %q have inconsistent default-selected: %s and %s", groupName, defaultSelected, entry.DefaultSelected)
			}
		}
	}
	if groupType == "" {
		groupType = "select"
	}
	if _, ok := multipleProxyGroupTypes[groupType]; !ok {
		return nil, fmt.Errorf("multiple-proxy: matchs for %q use unsupported group type: %s", groupName, groupType)
	}
	if defaultSelected != "" && groupType != "select" {
		return nil, fmt.Errorf("multiple-proxy: matchs for %q: default-selected is only supported on select groups, not %s", groupName, groupType)
	}

	matched := make([]string, 0, len(proxies))
	for name, p := range proxies {
		if !isMatchableProxy(name, p) {
			continue
		}
		for _, entry := range entries {
			if matchesAnyAlternative(entry.Name, name) {
				matched = append(matched, name)
				break
			}
		}
	}
	sort.Strings(matched)

	if len(matched) == 0 {
		return nil, fmt.Errorf("multiple-proxy: matchs for %q matched 0 proxies", groupName)
	}

	if defaultSelected != "" && !slices.Contains(matched, defaultSelected) {
		return nil, fmt.Errorf("multiple-proxy: matchs for %q default-selected %q is not in the matched proxies", groupName, defaultSelected)
	}

	mapping := map[string]any{
		"name":    groupName,
		"type":    groupType,
		"proxies": matched,
	}
	if defaultSelected != "" {
		mapping["default-selected"] = defaultSelected
	}

	group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("multiple-proxy: build group %q: %w", groupName, err)
	}

	p := adapter.NewProxy(group)
	proxies[groupName] = p
	return p, nil
}

// matchesAnyAlternative reports whether name matches any `|` separated
// alternative of pattern.
func matchesAnyAlternative(pattern, name string) bool {
	for _, alt := range strings.Split(pattern, "|") {
		if wildcard.Match(alt, name) {
			return true
		}
	}
	return false
}

// buildPortRuleSet merges a multiple-proxy entry's own rules into a port-scoped
// rule set. It returns ("", nil) when the entry has no routing intent. Otherwise
// the entry's rules are inserted before the last catch-all MATCH rule of the
// base, or appended when the base has none. The base is the global rules when
// enable-global-rule is set, and empty otherwise (entry rules only).
func buildPortRuleSet(rawRules []string, entry RawMultipleProxy, id string) (name string, merged []string) {
	if !entry.EnableGlobalRule && len(entry.Rules) == 0 {
		return "", nil
	}

	var base []string
	if entry.EnableGlobalRule {
		base = rawRules
	}

	insertAt := len(base)
	for i, line := range base {
		if tp, _, _, _ := RC.ParseRulePayload(line, false); tp == "MATCH" {
			insertAt = i
		}
	}

	merged = make([]string, 0, len(base)+len(entry.Rules))
	merged = append(merged, base[:insertAt]...)
	merged = append(merged, entry.Rules...)
	merged = append(merged, base[insertAt:]...)

	return id + "-rules", merged
}

// buildListenerMapping renders a multiple-proxy entry as a listeners: mapping.
// Optional keys are only emitted when set, so an entry without a rule set, mode
// or exit group leaves the corresponding listener behaviour at its default.
func buildListenerMapping(listenerName string, entry RawMultipleProxy, ltype string, port int, ruleSetName, exitGroup string) map[string]any {
	mapping := map[string]any{
		"type": ltype,
		"name": listenerName,
		"port": port,
	}
	if ruleSetName != "" {
		mapping["rule"] = ruleSetName
	}
	if entry.Mode != "" {
		mapping["mode"] = entry.Mode
	}
	if exitGroup != "" {
		mapping["fallback-proxy"] = exitGroup
	}
	return mapping
}

// parseMultipleProxy turns every multiple-proxy entry into an inbound listener,
// registering generated exit groups into proxies/providersMap and port-scoped
// rule sets into subRules. The listeners map is the one returned by
// parseListeners (the same object as Config.Listeners), so the existing
// listener lifecycle and reload diff apply unchanged. This function is additive:
// it never removes entries from listeners.
func parseMultipleProxy(cfg *RawConfig, proxies map[string]C.Proxy, providersMap map[string]P.ProxyProvider, ruleProviders map[string]P.RuleProvider, subRules map[string][]C.Rule, listeners map[string]C.InboundListener) error {
	used, err := collectUsedPorts(cfg)
	if err != nil {
		return err
	}

	for idx, entry := range cfg.MultipleProxy {
		id := multipleProxyID(entry, idx)
		listenerName := id

		ltype, port, err := multipleProxyListenerType(entry)
		if err != nil {
			return err
		}

		if err = validateMultipleProxyMode(entry.Mode); err != nil {
			return err
		}

		owner := "multiple-proxy " + id
		if other, conflict := used[uint16(port)]; conflict {
			return fmt.Errorf("%s: port %d conflicts with %s", owner, port, other)
		}
		used[uint16(port)] = owner

		exitGroup := ""
		if entry.ProxyGroup != "" {
			if _, exist := proxies[entry.ProxyGroup]; !exist {
				return fmt.Errorf("%s: proxy-group %q not found", multipleProxyEntryPrefix(entry), entry.ProxyGroup)
			}
			exitGroup = entry.ProxyGroup
		}
		if len(entry.Matchs) > 0 {
			groupName := id + "-group"
			if _, exist := proxies[groupName]; exist {
				return fmt.Errorf("%s: generated group %q already exists", multipleProxyEntryPrefix(entry), groupName)
			}
			if _, err = buildMatchsGroup(groupName, entry.Matchs, proxies, providersMap); err != nil {
				return err
			}
			if exitGroup == "" {
				exitGroup = groupName
			}
		}

		ruleName, merged := buildPortRuleSet(cfg.Rule, entry, id)
		if ruleName != "" {
			if _, exist := subRules[ruleName]; exist {
				return fmt.Errorf("%s: generated rule set %q already exists", multipleProxyEntryPrefix(entry), ruleName)
			}
			compiled, err := parseRules(merged, proxies, ruleProviders, subRules, "multiple-proxy["+id+"]")
			if err != nil {
				return err
			}
			subRules[ruleName] = compiled
		}

		mapping := buildListenerMapping(listenerName, entry, ltype, port, ruleName, exitGroup)
		l, err := listener.ParseListener(mapping)
		if err != nil {
			return fmt.Errorf("%s: %w", multipleProxyEntryPrefix(entry), err)
		}
		if _, exist := listeners[listenerName]; exist {
			return fmt.Errorf("listener %s is the duplicate name", listenerName)
		}
		listeners[listenerName] = l
	}

	return nil
}
