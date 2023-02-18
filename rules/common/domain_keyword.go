package common

import (
	"golang.org/x/net/idna"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainKeyword struct {
	*Base
	keyword string
	adapter string
	isIDNA  bool
}

func (dk *DomainKeyword) RuleType() C.RuleType {
	return C.DomainKeyword
}

func (dk *DomainKeyword) Match(metadata *C.Metadata) (bool, string) {
	domain := metadata.RuleHost()
	return strings.Contains(domain, dk.keyword), dk.adapter
}

func (dk *DomainKeyword) Adapter() string {
	return dk.adapter
}

func (dk *DomainKeyword) Payload() string {
	keyword := dk.keyword
	if dk.isIDNA {
		keyword, _ = idna.ToUnicode(keyword)
	}
	return keyword
}

func NewDomainKeyword(keyword string, adapter string) *DomainKeyword {
	actualDomainKeyword, _ := idna.ToASCII(keyword)
	return &DomainKeyword{
		Base:    &Base{},
		keyword: strings.ToLower(actualDomainKeyword),
		adapter: adapter,
		isIDNA:  keyword != actualDomainKeyword,
	}
}

//var _ C.Rule = (*DomainKeyword)(nil)
