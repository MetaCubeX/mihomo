package rules

import (
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainSuffix struct {
	suffix  string
	adapter string
}

func (ds *DomainSuffix) RuleType() C.RuleType {
	return C.DomainSuffix
}

func (ds *DomainSuffix) IsMatch(addr *C.Addr) bool {
	if addr.AddrType != C.AtypDomainName {
		return false
	}
	domain := addr.Host
	return strings.HasSuffix(domain, "."+ds.suffix) || domain == ds.suffix
}

func (ds *DomainSuffix) Adapter() string {
	return ds.adapter
}

func (ds *DomainSuffix) Payload() string {
	return ds.suffix
}

func NewDomainSuffix(suffix string, adapter string) *DomainSuffix {
	return &DomainSuffix{
		suffix:  suffix,
		adapter: adapter,
	}
}
