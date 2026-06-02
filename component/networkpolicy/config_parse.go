package networkpolicy

import (
	"fmt"

	"golang.org/x/exp/slices"
)

// ParseNetworks parses the top-level YAML `networks:` list into a []Network.
//
// Each entry must have exactly these keys:
//   - `name`: non-empty string; must not equal DefaultKey ("default") or
//     MatchedNone ("<none>") (both are reserved sentinels); must be unique
//     within the list.
//   - `match`: non-empty map, parsed by ParseMatch.
//
// Any unknown top-level key, duplicate name, or parse error on match block
// is fail-fast. Empty / nil input returns (nil, nil) so the top-level may
// simply omit the field.
func ParseNetworks(raw []map[string]any) ([]Network, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]Network, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for i, entry := range raw {
		if len(entry) == 0 {
			return nil, fmt.Errorf("networks[%d]: empty entry", i)
		}
		for k := range entry {
			switch k {
			case "name", "match":
			default:
				return nil, fmt.Errorf("networks[%d]: unknown key %q", i, k)
			}
		}
		nameAny, ok := entry["name"]
		if !ok {
			return nil, fmt.Errorf("networks[%d]: missing name", i)
		}
		name, ok := nameAny.(string)
		if !ok {
			return nil, fmt.Errorf("networks[%d]: name must be string, got %T", i, nameAny)
		}
		if name == "" {
			return nil, fmt.Errorf("networks[%d]: name cannot be empty", i)
		}
		if name == DefaultKey || name == MatchedNone {
			return nil, fmt.Errorf("networks[%d]: name %q is reserved", i, name)
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("networks[%d]: duplicate name %q", i, name)
		}
		seen[name] = struct{}{}

		matchAny, ok := entry["match"]
		if !ok {
			return nil, fmt.Errorf("networks[%d] (%q): missing match block", i, name)
		}
		matchMap, ok := matchAny.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("networks[%d] (%q): match must be a map, got %T", i, name, matchAny)
		}
		m, err := ParseMatch(matchMap)
		if err != nil {
			return nil, fmt.Errorf("networks[%d] (%q): %w", i, name, err)
		}

		out = append(out, Network{Name: name, Matcher: m})
	}
	return out, nil
}

// ParseGroupPolicy parses a select proxy-group's `network-policy:` subtree
// into a GroupPolicy, validating every key and value against the group's
// candidate set and the global proxy name set.
//
// Arguments:
//   - raw: the network-policy subtree (expected map[string]any where keys
//     are network names plus the optional reserved key DefaultKey)
//   - networkNames: the set of all valid network names defined under the
//     top-level networks: list (reserved DefaultKey is accepted in addition
//     and does not need to be in this list)
//   - globalProxyNames: the set of all parse-time-known proxy names
//     (built-ins + top-level `proxies:` + proxy group names; anything
//     resolvable via the kernel's proxyMap at parse time). Used to enforce
//     architecture §5.8.1 row 4 — "exists globally but not in this group's
//     sources" and "doesn't exist anywhere" both fail fast, regardless of
//     HasProvider. Provider expansions contribute names disjoint from this
//     set, so a target ∉ globalProxyNames is the only case where the
//     provider-tolerant branch applies.
//   - source: the group's parse-time candidate-set metadata (see GroupSource).
//
// Validation (architecture §5.8.1):
//   - Each key must either be in networkNames or equal DefaultKey.
//   - Each value (target proxy name) is non-empty and either:
//   - in source.StaticProxies (parse-time visible, fail-fast on miss from
//     the group's own candidate set);
//   - not in globalProxyNames AND source.HasProvider is true (tolerant:
//     target may come from a subscription; runtime reports missing_target
//     if absent on the first PUT);
//   - any other case (globally known but unreachable from this group; or
//     unknown everywhere with no provider attached) is a parse-time error.
//   - Empty raw map is rejected — network-policy: present but empty is a
//     likely typo; users who want "no policy" should omit the field.
func ParseGroupPolicy(raw any, networkNames []string, globalProxyNames []string, source GroupSource) (GroupPolicy, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return GroupPolicy{}, fmt.Errorf("network-policy: expected map, got %T", raw)
	}
	if len(m) == 0 {
		return GroupPolicy{}, fmt.Errorf("network-policy: empty map not allowed (omit the field to disable)")
	}

	policy := GroupPolicy{Mapping: make(map[string]string, len(m))}
	for key, v := range m {
		// Key validation first: reject reserved sentinel and unknown networks
		// before looking at the target. Ordering matters — if a user writes
		// `<none>: 42`, the real error is the reserved key, not the non-string
		// target.  DefaultKey is accepted without appearing in networkNames
		// since it is the policy-layer fallback key, not a network.
		isDefault := key == DefaultKey
		if key == MatchedNone {
			return GroupPolicy{}, fmt.Errorf("network-policy[%q]: reserved sentinel, not a valid network name", key)
		}
		if !isDefault && !slices.Contains(networkNames, key) {
			return GroupPolicy{}, fmt.Errorf("network-policy[%q]: unknown network (not defined in top-level networks:)", key)
		}

		// Target shape check.
		target, ok := v.(string)
		if !ok {
			return GroupPolicy{}, fmt.Errorf("network-policy[%q]: target must be string, got %T", key, v)
		}
		if target == "" {
			return GroupPolicy{}, fmt.Errorf("network-policy[%q]: target cannot be empty", key)
		}

		// Target reachability split (architecture §5.8.1):
		//   1) target ∈ StaticProxies → parse-time visible → OK
		//   2) target ∈ globalProxyNames but ∉ StaticProxies → fail-fast:
		//      the name exists elsewhere in the kernel's proxy namespace but
		//      this group can't reach it. Architecture treats provider-emitted
		//      names as disjoint from the global set, so a use-only group
		//      whose subscription happens to expose a node whose name
		//      collides with a global proxy still fails here — users must
		//      either add the target to this group's proxies: or rename the
		//      colliding global name. The error message flags both options.
		//   3) target ∉ globalProxyNames && HasProvider → tolerant (may
		//      be populated by subscription after provider first-load)
		//   4) target ∉ globalProxyNames && !HasProvider → fail-fast:
		//      name doesn't exist anywhere and there's no provider that
		//      could supply it later
		switch {
		case slices.Contains(source.StaticProxies, target):
			// case 1: OK
		case slices.Contains(globalProxyNames, target):
			// case 2
			return GroupPolicy{}, fmt.Errorf("network-policy[%q]: target %q is defined globally but is not reachable by this group (add %q to this group's proxies:, pick a target already in the group, or if you meant a provider node with the same name, rename it to disambiguate)", key, target, target)
		case source.HasProvider:
			// case 3: tolerant
		default:
			// case 4
			return GroupPolicy{}, fmt.Errorf("network-policy[%q]: target %q not found anywhere (add %q to proxies:, attach a provider via use:, or set include-all-providers: true)", key, target, target)
		}

		// All checks passed; commit to the policy only now.
		if isDefault {
			policy.HasDefault = true
			policy.DefaultProxy = target
		} else {
			policy.Mapping[key] = target
		}
	}
	return policy, nil
}
