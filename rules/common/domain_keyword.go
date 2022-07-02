package common

import (
	"golang.org/x/net/idna"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainKeyword struct {
	*Base
	keyword    string
	adapter    string
	rawKeyword string
}

func (dk *DomainKeyword) RuleType() C.RuleType {
	return C.DomainKeyword
}

func (dk *DomainKeyword) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}
	domain := metadata.Host
	return strings.Contains(domain, dk.keyword)
}

func (dk *DomainKeyword) Adapter() string {
	return dk.adapter
}

func (dk *DomainKeyword) Payload() string {
	return dk.rawKeyword
}

func NewDomainKeyword(keyword string, adapter string) *DomainKeyword {
	actualDomainKeyword, _ := idna.ToASCII(keyword)
	return &DomainKeyword{
		Base:       &Base{},
		keyword:    strings.ToLower(actualDomainKeyword),
		adapter:    adapter,
		rawKeyword: keyword,
	}
}

var _ C.Rule = (*DomainKeyword)(nil)
