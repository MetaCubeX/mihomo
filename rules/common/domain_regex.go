package common

import (
	"regexp"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type DomainRegex struct {
	*Base
	regex   string
	adapter string
}

func (dr *DomainRegex) RuleType() C.RuleType {
	return C.DomainRegex
}

func (dr *DomainRegex) Match(metadata *C.Metadata) (bool, string) {
	domain := metadata.RuleHost()
	match, _ := regexp.MatchString(dr.regex, domain)
	return match, dr.adapter
}

func (dr *DomainRegex) Adapter() string {
	return dr.adapter
}

func (dr *DomainRegex) Payload() string {
	return dr.regex
}

func NewDomainRegex(regex string, adapter string) *DomainRegex {
	return &DomainRegex{
		Base:    &Base{},
		regex:   strings.ToLower(regex),
		adapter: adapter,
	}
}

//var _ C.Rule = (*DomainRegex)(nil)
