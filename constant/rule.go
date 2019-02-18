package constant

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	GEOIP
	IPCIDR
	SourceIPCIDR
	MATCH
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
	case GEOIP:
		return "GEOIP"
	case IPCIDR:
		return "IPCIDR"
	case SourceIPCIDR:
		return "SourceIPCIDR"
	case MATCH:
		return "MATCH"
	default:
		return "Unknow"
	}
}

type Rule interface {
	RuleType() RuleType
	IsMatch(metadata *Metadata) bool
	Adapter() string
	Payload() string
}
