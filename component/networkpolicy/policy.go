package networkpolicy

const (
	// PersistVersion is the current schema version persisted alongside the
	// per-group last-matched network state in the runtime cache.
	PersistVersion = 1

	// MaxTTLSeconds is the upper bound on PUT /network/context TTL (10 years).
	// Keeps time.Duration well clear of its int64 nanosecond overflow (~292 years)
	// and prevents AfterFunc from scheduling absurdly far in the future.
	MaxTTLSeconds = 10 * 365 * 86400

	// DefaultKey is the reserved network-policy key meaning "fallback".
	DefaultKey = "default"

	// MatchedNone is the internal sentinel for "no context matched any network".
	// Used only in persisted per-group state and logs; REST responses serialize
	// matched_network as JSON null, not this string.
	MatchedNone = "<none>"

	// Selection source tri-state.
	SourceAuto    = "auto"
	SourceManual  = "manual"
	SourceUnknown = "unknown"
)

// Reason enumeration for the per-group resolution outcome surfaced via
// applied[].reason in the REST response.
const (
	ReasonMatched           = "matched"
	ReasonAlreadySelected   = "already_selected"
	ReasonDefault           = "default"
	ReasonNoChangeNoDefault = "no_change_no_default"
	ReasonUnchangedNetwork  = "unchanged_network"
	ReasonManualLocked      = "manual_locked"
	ReasonMissingTarget     = "missing_target"
)

// GroupPolicy is the network-policy: field of a select proxy-group.
type GroupPolicy struct {
	// Mapping is network name → proxy name (never contains "default").
	Mapping map[string]string

	// HasDefault reports whether the YAML explicitly set a default key.
	HasDefault bool

	// DefaultProxy is the value of the default key (valid iff HasDefault).
	DefaultProxy string
}

// IsEmpty reports whether the group declares no policy at all.
func (p GroupPolicy) IsEmpty() bool {
	return len(p.Mapping) == 0 && !p.HasDefault
}

// Resolve maps a matched network name to the target proxy and a reason.
// matched == "" means "no network matched".
//
// Returns:
//   - (Mapping[matched], ReasonMatched) when matched is non-empty and in Mapping.
//   - (DefaultProxy, ReasonDefault) when no mapping hits but HasDefault is true.
//   - ("", ReasonNoChangeNoDefault) otherwise.
//
// Resolve does not know the currently-selected proxy, so it never returns
// ReasonAlreadySelected; the runtime state machine classifies that case.
func (p GroupPolicy) Resolve(matched string) (target, reason string) {
	if matched != "" {
		if t, ok := p.Mapping[matched]; ok {
			return t, ReasonMatched
		}
	}
	if p.HasDefault {
		return p.DefaultProxy, ReasonDefault
	}
	return "", ReasonNoChangeNoDefault
}

// GroupSource records parse-time metadata about a proxy-group's candidate
// set. Populated at YAML parse time; consumed by network-policy validation
// and by the runtime when deciding whether a target proxy is reachable.
type GroupSource struct {
	// StaticProxies is the set of candidate names resolvable at parse time:
	//   - names listed explicitly under proxies:
	//   - names from include-all / include-all-proxies expansion, after applying
	//     Filter / ExcludeFilter / ExcludeType
	// Must already reflect the final filter result, so that a target present here
	// is guaranteed reachable by the runtime (subject to provider refresh).
	StaticProxies []string

	// HasProvider reports whether the group has any provider attached after
	// include-all-providers / include-all expansion. Used by validation to
	// decide the tolerant (provider-backed) branch.
	HasProvider bool

	// Filter / ExcludeFilter / ExcludeType are the group's include-all filtering
	// rules, recorded for validation and debugging. The runtime does not consult
	// these directly—runtime filtering is handled by GroupBase.GetProxies.
	Filter        string
	ExcludeFilter string
	ExcludeType   string
}

// selectable is the narrowest interface the network-policy runtime needs to
// manually switch a proxy-group. Selector, Fallback, and URLTest all satisfy
// it; kept unexported because no caller outside this package needs to
// reference the name — SelectorWithPolicy embeds it and callers interact
// with the composed interface.
type selectable interface {
	Name() string
	Set(name string) error
}

// SelectorWithPolicy is the full interface for a select-type group that
// carries network-policy metadata. Only *outboundgroup.Selector satisfies it.
// The runtime state machine and first-init logic depend on Now / HasProxy /
// NetworkPolicy / GroupSource in addition to the selectable base methods.
//
// Exported so the executor can build []SelectorWithPolicy from the parsed
// proxy map and hand it to NewManager / Install.
type SelectorWithPolicy interface {
	selectable
	Now() string
	HasProxy(name string) bool
	NetworkPolicy() GroupPolicy
	GroupSource() GroupSource
}
