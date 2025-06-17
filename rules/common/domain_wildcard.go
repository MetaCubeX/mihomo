package common

import (
	"strings"

	"github.com/metacubex/mihomo/component/wildcard"
	C "github.com/metacubex/mihomo/constant"
)

type DomainWildcard struct {
	*Base
	pattern string
	adapter string
}

func (dw *DomainWildcard) RuleType() C.RuleType {
	return C.DomainWildcard
}

func (dw *DomainWildcard) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	return wildcard.Match(dw.pattern, metadata.Host), dw.adapter
}

func (dw *DomainWildcard) Adapter() string {
	return dw.adapter
}

func (dw *DomainWildcard) Payload() string {
	return dw.pattern
}

var _ C.Rule = (*DomainWildcard)(nil)

func NewDomainWildcard(pattern string, adapter string) (*DomainWildcard, error) {
	pattern = strings.ToLower(pattern)
	return &DomainWildcard{
		Base:    &Base{},
		pattern: pattern,
		adapter: adapter,
	}, nil
}
