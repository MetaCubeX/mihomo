package rules

import (
	C "github.com/Dreamacro/clash/constant"
)

type Domain struct {
	domain  string
	adapter string
}

func (d *Domain) RuleType() C.RuleType {
	return C.Domain
}

func (d *Domain) IsMatch(addr *C.Addr) bool {
	if addr.AddrType != C.AtypDomainName {
		return false
	}
	return addr.Host == d.domain
}

func (d *Domain) Adapter() string {
	return d.adapter
}

func (d *Domain) Payload() string {
	return d.domain
}

func NewDomain(domain string, adapter string) *Domain {
	return &Domain{
		domain:  domain,
		adapter: adapter,
	}
}
