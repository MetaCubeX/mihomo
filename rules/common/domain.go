package common

import (
	"golang.org/x/net/idna"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type Domain struct {
	*Base
	domain  string
	adapter string
	isIDNA  bool
}

func (d *Domain) RuleType() C.RuleType {
	return C.Domain
}

func (d *Domain) Match(metadata *C.Metadata) (bool, string) {
	return metadata.RuleHost() == d.domain, d.adapter
}

func (d *Domain) Adapter() string {
	return d.adapter
}

func (d *Domain) Payload() string {
	domain := d.domain
	if d.isIDNA {
		domain, _ = idna.ToUnicode(domain)
	}
	return domain
}

func NewDomain(domain string, adapter string) *Domain {
	actualDomain, _ := idna.ToASCII(domain)
	return &Domain{
		Base:    &Base{},
		domain:  strings.ToLower(actualDomain),
		adapter: adapter,
		isIDNA:  actualDomain != domain,
	}
}

//var _ C.Rule = (*Domain)(nil)
