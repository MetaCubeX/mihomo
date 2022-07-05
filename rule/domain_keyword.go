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

func (dk *DomainKeyword) Match(metadata *C.Metadata) bool {
	return strings.Contains(metadata.Host, dk.keyword)
}

func (dk *DomainKeyword) Adapter() string {
	return dk.adapter
}

func (dk *DomainKeyword) Payload() string {
	return dk.keyword
}

func (dk *DomainKeyword) ShouldResolveIP() bool {
	return false
}

func (dk *DomainKeyword) ShouldFindProcess() bool {
	return false
}

func NewDomainKeyword(keyword string, adapter string) *DomainKeyword {
	return &DomainKeyword{
		keyword: strings.ToLower(keyword),
		adapter: adapter,
	}
}
