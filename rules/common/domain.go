package common

import (
	"golang.org/x/net/idna"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type Domain struct {
	*Base
	domain    string
	rawDomain string
	adapter   string
}

func (d *Domain) RuleType() C.RuleType {
	return C.Domain
}

func (d *Domain) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}
	return metadata.Host == d.domain
}

func (d *Domain) Adapter() string {
	return d.adapter
}

func (d *Domain) Payload() string {
	return d.rawDomain
}

func NewDomain(domain string, adapter string) *Domain {
	actualDomain, _ := idna.ToASCII(domain)
	return &Domain{
		Base:      &Base{},
		domain:    strings.ToLower(actualDomain),
		adapter:   adapter,
		rawDomain: domain,
	}
}

var _ C.Rule = (*Domain)(nil)
