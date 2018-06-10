package constant

// Rule Type
const (
	DomainSuffix RuleType = iota
	DomainKeyword
	GEOIP
	IPCIDR
	FINAL
)

type RuleType int

type Rule interface {
	RuleType() RuleType
	IsMatch(addr *Addr) bool
	Adapter() string
}
