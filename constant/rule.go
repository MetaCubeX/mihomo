package constant

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	GEOIP
	IPCIDR
	FINAL
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
	case FINAL:
		return "FINAL"
	default:
		return "Unknow"
	}
}

type Rule interface {
	RuleType() RuleType
	IsMatch(addr *Addr) bool
	Adapter() string
	Payload() string
}
