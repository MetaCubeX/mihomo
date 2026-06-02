package networkpolicy

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/exp/slices"
)

// Matcher decides whether a NetworkContext hits this rule. The top-level
// constructor ParseMatch returns a Matcher; concrete implementations are
// matchBlock and logical combinators (anyMatcher/allMatcher/notMatcher).
type Matcher interface {
	Match(ctx *NetworkContext) bool
}

// matchBlock is the AST node for a single YAML `match:` sub-tree.
//
// Compile model (three-tuple):
//
//	P = atomic conjunction of per-iface-field predicates (len(ifacePred) > 0)
//	G = global-field predicate (single Matcher on ctx, currently dns-suffix)
//	C = list of combinator sub-blocks (any:/all:/not:)
//
// Evaluation:
//
//	block ≡ (P_empty ? true : ∃iface ∈ interfaces . P(iface)) ∧ G ∧ C_1 ∧ … ∧ C_n
//
// The "∃ only wraps when P is non-empty" rule lets blocks with only global
// fields / combinators still match on interfaces[] = [] — the typical use
// case being "not: { iface-type: cellular }" holding on an empty inventory.
//
// Atomicity: the per-iface fields inside one block are required to hold on
// the SAME iface — that's what makes ifacePred a conjunction evaluated
// per-iface instead of "∃iface f1 ∧ ∃iface f2" (which would let two
// different ifaces satisfy one field each).
type matchBlock struct {
	ifacePred   ifacePred // nil/empty → P_empty (no ∃ wrap)
	globalPred  Matcher   // nil → absent
	combinators []Matcher
}

// Match implements Matcher. Returns false for nil ctx (rather than panic) so
// callers can treat Matcher as a total function; the top-level Match(ctx)
// also guards against nil, but the public Matcher surface should be safe
// on its own.
func (b matchBlock) Match(ctx *NetworkContext) bool {
	if ctx == nil {
		return false
	}
	if len(b.ifacePred) > 0 {
		hit := false
		for i := range ctx.Interfaces {
			if b.ifacePred.matchIface(&ctx.Interfaces[i]) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if b.globalPred != nil && !b.globalPred.Match(ctx) {
		return false
	}
	for _, c := range b.combinators {
		if !c.Match(ctx) {
			return false
		}
	}
	return true
}

// ifaceFieldMatcher is the per-iface predicate building block. Each
// implementation evaluates one field of a single InterfaceContext.
//
// Null-field semantics: a field the sampler didn't populate makes matchIface
// return false for that iface. This excludes null-field ifaces from the ∃
// domain (rather than treating null as "any value"), which also means a
// `not:` wrapped over a matcher of a field no iface reports is true — "no
// iface satisfies the predicate" is the natural reading.
type ifaceFieldMatcher interface {
	matchIface(iface *InterfaceContext) bool
}

// ifacePred is the atomic AND of per-iface field matchers.
type ifacePred []ifaceFieldMatcher

func (p ifacePred) matchIface(iface *InterfaceContext) bool {
	for _, m := range p {
		if !m.matchIface(iface) {
			return false
		}
	}
	return true
}

// -------------------- per-iface field matchers --------------------

type nameFieldMatcher struct{ values []string }

func (m nameFieldMatcher) matchIface(iface *InterfaceContext) bool {
	return iface.Name != "" && slices.Contains(m.values, iface.Name)
}

type ifaceTypeFieldMatcher struct{ values []string }

func (m ifaceTypeFieldMatcher) matchIface(iface *InterfaceContext) bool {
	return iface.IfaceType != "" && slices.Contains(m.values, iface.IfaceType)
}

type ssidFieldMatcher struct{ values []string }

func (m ssidFieldMatcher) matchIface(iface *InterfaceContext) bool {
	return iface.SSID != "" && slices.Contains(m.values, iface.SSID)
}

type bssidFieldMatcher struct{ values []string }

func (m bssidFieldMatcher) matchIface(iface *InterfaceContext) bool {
	return iface.BSSID != "" && slices.Contains(m.values, iface.BSSID)
}

type gatewayMACFieldMatcher struct{ values []string }

func (m gatewayMACFieldMatcher) matchIface(iface *InterfaceContext) bool {
	return iface.GatewayMAC != "" && slices.Contains(m.values, iface.GatewayMAC)
}

type gatewayIPFieldMatcher struct{ matches []ipMatcher }

func (m gatewayIPFieldMatcher) matchIface(iface *InterfaceContext) bool {
	if !iface.gatewayIPParsed.IsValid() {
		return false
	}
	for _, im := range m.matches {
		if im.match(iface.gatewayIPParsed) {
			return true
		}
	}
	return false
}

type subnetsFieldMatcher struct{ prefixes []netip.Prefix }

func (m subnetsFieldMatcher) matchIface(iface *InterfaceContext) bool {
	if len(iface.subnetsParsed) == 0 {
		return false
	}
	for _, p := range m.prefixes {
		for _, q := range iface.subnetsParsed {
			if p.Overlaps(q) {
				return true
			}
		}
	}
	return false
}

// ipMatcher represents a single IP or CIDR entry for gateway-ip.
type ipMatcher struct {
	addr   netip.Addr
	prefix netip.Prefix
	isCIDR bool
}

func (m ipMatcher) match(got netip.Addr) bool {
	if m.isCIDR {
		return m.prefix.Contains(got)
	}
	return m.addr == got
}

// -------------------- global matchers --------------------

// dnsSuffixMatcher evaluates the top-level dns_suffix field. Match semantics:
// intersection of matcher values (lower-cased at parse time) with ctx.DNSSuffix
// (lower-cased at normalize time) is non-empty.
type dnsSuffixMatcher struct{ values []string }

func (m dnsSuffixMatcher) Match(ctx *NetworkContext) bool {
	if ctx == nil || len(ctx.DNSSuffix) == 0 {
		return false
	}
	for _, v := range m.values {
		if slices.Contains(ctx.DNSSuffix, v) {
			return true
		}
	}
	return false
}

// -------------------- combinators --------------------

type anyMatcher []Matcher

func (m anyMatcher) Match(ctx *NetworkContext) bool {
	for _, sub := range m {
		if sub.Match(ctx) {
			return true
		}
	}
	return false
}

type allMatcher []Matcher

func (m allMatcher) Match(ctx *NetworkContext) bool {
	for _, sub := range m {
		if !sub.Match(ctx) {
			return false
		}
	}
	return true
}

type notMatcher struct{ inner Matcher }

func (m notMatcher) Match(ctx *NetworkContext) bool {
	// Conservative nil guard: nil ctx → no match (rather than double-negate
	// through to true). Keeps the entire Matcher surface nil-safe with the
	// unified "no ctx means no match" reading.
	if ctx == nil {
		return false
	}
	return !m.inner.Match(ctx)
}

// -------------------- parser --------------------

// ParseMatch parses a YAML match: sub-tree into a Matcher. Empty raw map is
// rejected — a block with no fields has no meaningful semantic.
func ParseMatch(raw map[string]any) (Matcher, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty match block: require at least one field")
	}
	// Sort keys for deterministic error reporting on malformed blocks.
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var fields []ifaceFieldMatcher
	var combinators []Matcher
	var globalPred Matcher

	for _, key := range keys {
		val := raw[key]
		switch key {
		case "any":
			sub, err := parseAny(val)
			if err != nil {
				return nil, err
			}
			combinators = append(combinators, sub)
		case "all":
			sub, err := parseAll(val)
			if err != nil {
				return nil, err
			}
			combinators = append(combinators, sub)
		case "not":
			sub, err := parseNot(val)
			if err != nil {
				return nil, err
			}
			combinators = append(combinators, sub)
		case "dns-suffix":
			m, err := buildDNSSuffixMatcher(val)
			if err != nil {
				return nil, err
			}
			globalPred = m
		case "name", "iface-type", "ssid", "bssid", "gateway-ip", "gateway-mac", "subnets":
			m, err := buildIfaceFieldMatcher(key, val)
			if err != nil {
				return nil, err
			}
			fields = append(fields, m)
		case "metered":
			// The metered matcher is deliberately disabled until host sampler
			// implementations populate InterfaceContext.Metered reliably.
			// While all platforms emit Metered=null, `not: {metered: true}`
			// would silently always-match (∃iface with Metered==true is
			// false, negation is true), which is surprising. The wire field
			// is still parsed (forward-compat) but YAML references are
			// rejected at config-load time with an actionable alternative.
			return nil, fmt.Errorf("match.metered: not supported (host samplers do not yet populate metered; use iface-type: cellular / wwan instead)")
		default:
			return nil, fmt.Errorf("unknown match key: %q", key)
		}
	}

	block := matchBlock{
		globalPred:  globalPred,
		combinators: combinators,
	}
	if len(fields) > 0 {
		block.ifacePred = ifacePred(fields)
	}
	return block, nil
}

func parseAny(v any) (Matcher, error) {
	subs, err := parseSubBlocks("any", v)
	if err != nil {
		return nil, err
	}
	if len(subs) == 1 {
		return subs[0], nil
	}
	return anyMatcher(subs), nil
}

func parseAll(v any) (Matcher, error) {
	subs, err := parseSubBlocks("all", v)
	if err != nil {
		return nil, err
	}
	if len(subs) == 1 {
		return subs[0], nil
	}
	return allMatcher(subs), nil
}

func parseNot(v any) (Matcher, error) {
	// `not:` takes exactly one match-block, never a list. This asymmetry
	// with any:/all: mirrors boolean logic (NOT is unary).
	sub, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("match.not: expected map (single match-block), got %T", v)
	}
	inner, err := ParseMatch(sub)
	if err != nil {
		return nil, fmt.Errorf("match.not: %w", err)
	}
	return notMatcher{inner: inner}, nil
}

func parseSubBlocks(opName string, v any) ([]Matcher, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("match.%s: expected list of sub-matches", opName)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("match.%s: at least one sub-match required", opName)
	}
	subs := make([]Matcher, 0, len(list))
	for i, item := range list {
		sub, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("match.%s[%d]: expected map, got %T", opName, i, item)
		}
		m, err := ParseMatch(sub)
		if err != nil {
			return nil, fmt.Errorf("match.%s[%d]: %w", opName, i, err)
		}
		subs = append(subs, m)
	}
	return subs, nil
}

func buildIfaceFieldMatcher(key string, val any) (ifaceFieldMatcher, error) {
	switch key {
	case "name":
		list, err := coerceStringList(key, val)
		if err != nil {
			return nil, err
		}
		return nameFieldMatcher{values: list}, nil

	case "iface-type":
		list, err := coerceStringList(key, val)
		if err != nil {
			return nil, err
		}
		for i := range list {
			list[i] = strings.ToLower(list[i])
			if !isValidIfaceType(list[i]) {
				return nil, fmt.Errorf("iface-type[%d]: invalid value %q", i, list[i])
			}
		}
		return ifaceTypeFieldMatcher{values: list}, nil

	case "ssid":
		list, err := coerceStringList(key, val)
		if err != nil {
			return nil, err
		}
		return ssidFieldMatcher{values: list}, nil

	case "bssid":
		list, err := coerceStringList(key, val)
		if err != nil {
			return nil, err
		}
		for i, s := range list {
			m, err := normalizeMAC(s)
			if err != nil {
				return nil, fmt.Errorf("bssid[%d]: %w", i, err)
			}
			list[i] = m
		}
		return bssidFieldMatcher{values: list}, nil

	case "gateway-mac":
		list, err := coerceStringList(key, val)
		if err != nil {
			return nil, err
		}
		for i, s := range list {
			m, err := normalizeMAC(s)
			if err != nil {
				return nil, fmt.Errorf("gateway-mac[%d]: %w", i, err)
			}
			list[i] = m
		}
		return gatewayMACFieldMatcher{values: list}, nil

	case "gateway-ip":
		list, err := coerceStringList(key, val)
		if err != nil {
			return nil, err
		}
		matches := make([]ipMatcher, 0, len(list))
		for i, s := range list {
			im, err := parseIPMatcher(s)
			if err != nil {
				return nil, fmt.Errorf("gateway-ip[%d]: %q: %w", i, s, err)
			}
			matches = append(matches, im)
		}
		return gatewayIPFieldMatcher{matches: matches}, nil

	case "subnets":
		list, err := coerceStringList(key, val)
		if err != nil {
			return nil, err
		}
		prefixes := make([]netip.Prefix, 0, len(list))
		for i, s := range list {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("subnets[%d]: %q: %w", i, s, err)
			}
			prefixes = append(prefixes, p.Masked())
		}
		return subnetsFieldMatcher{prefixes: prefixes}, nil
	}
	return nil, fmt.Errorf("unknown iface field key: %q", key)
}

func buildDNSSuffixMatcher(val any) (Matcher, error) {
	list, err := coerceStringList("dns-suffix", val)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i] = strings.ToLower(list[i])
	}
	return dnsSuffixMatcher{values: list}, nil
}

func parseIPMatcher(s string) (ipMatcher, error) {
	if strings.ContainsRune(s, '/') {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return ipMatcher{}, err
		}
		return ipMatcher{prefix: p.Masked(), isCIDR: true}, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return ipMatcher{}, err
	}
	// Strip IPv6 zone to align with context-side normalize() behavior.
	return ipMatcher{addr: addr.WithZone("")}, nil
}

// coerceStringList turns a YAML-decoded value into []string, rejecting loose
// type coercions (numbers are not silently stringified). Empty list/string
// is a hard error so that a match-block is never trivially-satisfiable.
func coerceStringList(ctx string, v any) ([]string, error) {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil, fmt.Errorf("%s: empty string not allowed", ctx)
		}
		return []string{x}, nil
	case []string:
		if len(x) == 0 {
			return nil, fmt.Errorf("%s: empty list not allowed", ctx)
		}
		out := make([]string, len(x))
		for i, s := range x {
			if s == "" {
				return nil, fmt.Errorf("%s[%d]: empty string not allowed", ctx, i)
			}
			out[i] = s
		}
		return out, nil
	case []any:
		if len(x) == 0 {
			return nil, fmt.Errorf("%s: empty list not allowed", ctx)
		}
		out := make([]string, 0, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d]: expected string, got %T", ctx, i, item)
			}
			if s == "" {
				return nil, fmt.Errorf("%s[%d]: empty string not allowed", ctx, i)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: expected string or list, got %T", ctx, v)
	}
}
