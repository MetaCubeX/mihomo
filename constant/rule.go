package constant

import "time"

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	DomainRegex
	DomainWildcard
	GEOSITE
	GEOIP
	SrcGEOIP
	IPASN
	SrcIPASN
	IPCIDR
	SrcIPCIDR
	IPSuffix
	SrcIPSuffix
	SrcPort
	DstPort
	InPort
	DSCP
	InUser
	InName
	InType
	ProcessName
	ProcessPath
	ProcessNameRegex
	ProcessPathRegex
	ProcessNameWildcard
	ProcessPathWildcard
	RematchName
	RuleSet
	Network
	Uid
	SubRules
	MATCH
	AND
	OR
	NOT
)

type RuleType int

func (rt RuleType) String() string {
	switch rt {
	case Domain:
		return "Domain"
	case DomainSuffix:
		return "DomainSuffix"
	case DomainKeyword:
		return "DomainKeyword"
	case DomainRegex:
		return "DomainRegex"
	case DomainWildcard:
		return "DomainWildcard"
	case GEOSITE:
		return "GeoSite"
	case GEOIP:
		return "GeoIP"
	case SrcGEOIP:
		return "SrcGeoIP"
	case IPASN:
		return "IPASN"
	case SrcIPASN:
		return "SrcIPASN"
	case IPCIDR:
		return "IPCIDR"
	case SrcIPCIDR:
		return "SrcIPCIDR"
	case IPSuffix:
		return "IPSuffix"
	case SrcIPSuffix:
		return "SrcIPSuffix"
	case SrcPort:
		return "SrcPort"
	case DstPort:
		return "DstPort"
	case InPort:
		return "InPort"
	case InUser:
		return "InUser"
	case InName:
		return "InName"
	case InType:
		return "InType"
	case ProcessName:
		return "ProcessName"
	case ProcessPath:
		return "ProcessPath"
	case ProcessNameRegex:
		return "ProcessNameRegex"
	case ProcessPathRegex:
		return "ProcessPathRegex"
	case ProcessNameWildcard:
		return "ProcessNameWildcard"
	case ProcessPathWildcard:
		return "ProcessPathWildcard"
	case RematchName:
		return "RematchName"
	case MATCH:
		return "Match"
	case RuleSet:
		return "RuleSet"
	case Network:
		return "Network"
	case DSCP:
		return "DSCP"
	case Uid:
		return "Uid"
	case SubRules:
		return "SubRules"
	case AND:
		return "AND"
	case OR:
		return "OR"
	case NOT:
		return "NOT"
	default:
		return "Unknown"
	}
}

type Rule interface {
	RuleType() RuleType
	Match(metadata *Metadata, helper RuleMatchHelper) (bool, string)
	Adapter() string
	Payload() string
	ProviderNames() []string
}

type RuleWrapper interface {
	Rule

	// SetDisabled to set enable/disable rule
	SetDisabled(v bool)
	// IsDisabled return rule is disabled or not
	IsDisabled() bool

	// HitCount for statistics
	HitCount() uint64
	// HitAt for statistics
	HitAt() time.Time
	// MissCount for statistics
	MissCount() uint64
	// MissAt for statistics
	MissAt() time.Time

	// Unwrap return Rule
	Unwrap() Rule
}

type RuleMatchHelper struct {
	ResolveIP     func()
	FindProcess   func()
	CheckPassRule func(adapterName string) bool
	// Diagnostics is nil for live traffic and propagates through nested rules.
	Diagnostics *RuleMatchDiagnostics
}

// RuleMatchDiagnostics holds state for diagnostic evaluation, which does not record statistics.
type RuleMatchDiagnostics struct {
	BeforeMatch              func(Rule, *Metadata, *RuleMatchDiagnostics) bool
	AfterMatch               func(Rule, *Metadata, *RuleMatchDiagnostics) bool
	MatchProvider            func(string, *Metadata, RuleMatchHelper) bool
	SubRuleMatched           func(string, int, Rule)
	Incomplete               func() bool
	BeginRule                func()
	SourceDestinationSwapped bool
}

// OriginalField maps fields in a source-mode rule set back to request metadata.
func (d *RuleMatchDiagnostics) OriginalField(field string) string {
	if d.SourceDestinationSwapped {
		switch field {
		case "ip":
			return "source-ip"
		case "source-ip":
			return "ip"
		case "port":
			return "source-port"
		case "source-port":
			return "port"
		}
	}
	return field
}

// MatchRule evaluates a rule with optional diagnostic metadata checks.
func (h RuleMatchHelper) MatchRule(rule Rule, metadata *Metadata) (bool, string) {
	if h.Diagnostics == nil {
		return rule.Match(metadata, h)
	}
	if h.Diagnostics.Incomplete != nil && h.Diagnostics.Incomplete() {
		return false, ""
	}
	for {
		wrapper, ok := rule.(RuleWrapper)
		if !ok {
			break
		}
		if wrapper.IsDisabled() {
			return false, ""
		}
		rule = wrapper.Unwrap()
	}
	if h.Diagnostics.BeforeMatch != nil && !h.Diagnostics.BeforeMatch(rule, metadata, h.Diagnostics) {
		return false, ""
	}
	matched, adapter := rule.Match(metadata, h)
	if h.Diagnostics.AfterMatch != nil && !h.Diagnostics.AfterMatch(rule, metadata, h.Diagnostics) {
		return false, ""
	}
	if h.Diagnostics.Incomplete != nil && h.Diagnostics.Incomplete() {
		return false, ""
	}
	return matched, adapter
}

type RuleGroup interface {
	Rule
	GetRecodeSize() int
}
