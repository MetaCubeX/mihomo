package common

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/idna"
)

type DomainKeyword struct {
	*Base
	keyword string
	adapter string
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
	return dk.keyword
}

func NewDomainKeyword(keyword string, adapter string) *DomainKeyword {
	punycode, _ := idna.ToASCII(strings.ToLower(keyword))
	return &DomainKeyword{
		Base:    &Base{},
		keyword: punycode,
		adapter: adapter,
	}
}

//var _ C.Rule = (*DomainKeyword)(nil)
