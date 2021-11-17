package rules

import (
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainSuffix struct {
	suffix    string
	adapter   string
	ruleExtra *C.RuleExtra
}

func (ds *DomainSuffix) RuleType() C.RuleType {
	return C.DomainSuffix
}

func (ds *DomainSuffix) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}
	domain := metadata.Host
	return strings.HasSuffix(domain, "."+ds.suffix) || domain == ds.suffix
}

func (ds *DomainSuffix) Adapter() string {
	return ds.adapter
}

func (ds *DomainSuffix) Payload() string {
	return ds.suffix
}

func (ds *DomainSuffix) ShouldResolveIP() bool {
	return false
}

func (ds *DomainSuffix) RuleExtra() *C.RuleExtra {
	return ds.ruleExtra
}

func NewDomainSuffix(suffix string, adapter string, ruleExtra *C.RuleExtra) *DomainSuffix {
	return &DomainSuffix{
		suffix:    strings.ToLower(suffix),
		adapter:   adapter,
		ruleExtra: ruleExtra,
	}
}
