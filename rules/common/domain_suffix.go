package common

import (
	"golang.org/x/net/idna"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainSuffix struct {
	*Base
	suffix    string
	adapter   string
	rawSuffix string
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
	return ds.rawSuffix
}

func NewDomainSuffix(suffix string, adapter string) *DomainSuffix {
	actualDomainKeyword, _ := idna.ToASCII(suffix)
	return &DomainSuffix{
		Base:      &Base{},
		suffix:    strings.ToLower(actualDomainKeyword),
		adapter:   adapter,
		rawSuffix: suffix,
	}
}

var _ C.Rule = (*DomainSuffix)(nil)
