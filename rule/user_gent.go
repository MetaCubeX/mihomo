package rules

import (
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type UserAgent struct {
	*Base
	ua      string
	adapter string
}

func (d *UserAgent) RuleType() C.RuleType {
	return C.UserAgent
}

func (d *UserAgent) Match(metadata *C.Metadata) bool {
	if metadata.Type != C.MITM || metadata.UserAgent == "" {
		return false
	}

	return strings.Contains(metadata.UserAgent, d.ua)
}

func (d *UserAgent) Adapter() string {
	return d.adapter
}

func (d *UserAgent) Payload() string {
	return d.ua
}

func (d *UserAgent) ShouldResolveIP() bool {
	return false
}

func NewUserAgent(ua string, adapter string) (*UserAgent, error) {
	ua = strings.Trim(ua, "*")
	if ua == "" {
		return nil, errPayload
	}

	return &UserAgent{
		Base:    &Base{},
		ua:      ua,
		adapter: adapter,
	}, nil
}

var _ C.Rule = (*UserAgent)(nil)
