package constant

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	DomainRegex
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
	Match(metadata *Metadata) (bool, string)
	Adapter() string
	Payload() string
	ShouldResolveIP() bool
	ShouldFindProcess() bool
	ProviderNames() []string
}

type RuleGroup interface {
	Rule
	GetRecodeSize() int
}
