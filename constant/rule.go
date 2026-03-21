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
	ResolveIP   func()
	FindProcess func()
}

type RuleGroup interface {
	Rule
	GetRecodeSize() int
}
