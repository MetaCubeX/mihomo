package common

import (
	"regexp"

	C "github.com/metacubex/mihomo/constant"
)

type DomainRegex struct {
	*Base
	regex   *regexp.Regexp
	adapter string
}

func (dr *DomainRegex) RuleType() C.RuleType {
	return C.DomainRegex
}

func (dr *DomainRegex) Match(metadata *C.Metadata) (bool, string) {
	domain := metadata.RuleHost()
	return dr.regex.MatchString(domain), dr.adapter
}

func (dr *DomainRegex) Adapter() string {
	return dr.adapter
}

func (dr *DomainRegex) Payload() string {
	return dr.regex.String()
}

func NewDomainRegex(regex string, adapter string) (*DomainRegex, error) {
	r, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}
	return &DomainRegex{
		Base:    &Base{},
		regex:   r,
		adapter: adapter,
	}, nil
}

//var _ C.Rule = (*DomainRegex)(nil)
