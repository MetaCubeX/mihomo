package rules

import (
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainKeyword struct {
	keyword string
	adapter string
}

func (dk *DomainKeyword) RuleType() C.RuleType {
	return C.DomainKeyword
}

func (dk *DomainKeyword) IsMatch(addr *C.Addr) bool {
	if addr.AddrType != C.AtypDomainName {
		return false
	}
	domain := addr.Host
	return strings.Contains(domain, dk.keyword)
}

func (dk *DomainKeyword) Adapter() string {
	return dk.adapter
}

func NewDomainKeyword(keyword string, adapter string) *DomainKeyword {
	return &DomainKeyword{
		keyword: keyword,
		adapter: adapter,
	}
}
