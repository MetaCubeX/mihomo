package common

import (
	"golang.org/x/net/idna"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainSuffix struct {
	*Base
	suffix  string
	adapter string
	isIDNA  bool
}

func (ds *DomainSuffix) RuleType() C.RuleType {
	return C.DomainSuffix
}

func (ds *DomainSuffix) Match(metadata *C.Metadata) (bool, string) {
	domain := metadata.RuleHost()
	return strings.HasSuffix(domain, "."+ds.suffix) || domain == ds.suffix, ds.adapter
}

func (ds *DomainSuffix) Adapter() string {
	return ds.adapter
}

func (ds *DomainSuffix) Payload() string {
	suffix := ds.suffix
	if ds.isIDNA {
		suffix, _ = idna.ToUnicode(suffix)
	}
	return suffix
}

func NewDomainSuffix(suffix string, adapter string) *DomainSuffix {
	actualDomainSuffix, _ := idna.ToASCII(suffix)
	return &DomainSuffix{
		Base:    &Base{},
		suffix:  strings.ToLower(actualDomainSuffix),
		adapter: adapter,
		isIDNA:  suffix != actualDomainSuffix,
	}
}

//var _ C.Rule = (*DomainSuffix)(nil)
