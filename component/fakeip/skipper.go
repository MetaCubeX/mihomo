package fakeip

import (
	C "github.com/metacubex/mihomo/constant"
)

const (
	UseFakeIP = "fake-ip"
	UseRealIP = "real-ip"
)

type Skipper struct {
	Rules       []C.Rule
	DefaultMode string

	Host []C.DomainMatcher
	Mode C.FilterMode
}

// ShouldSkipped return if domain should be skipped
func (p *Skipper) ShouldSkipped(domain string) bool {
	if len(p.Rules) > 0 {
		metadata := &C.Metadata{Host: domain}
		for _, rule := range p.Rules {
			if matched, _ := rule.Match(metadata, C.RuleMatchHelper{}); matched {
				return rule.Adapter() == UseRealIP
			}
		}
		return p.DefaultMode == UseRealIP
	}

	should := p.shouldSkipped(domain)
	if p.Mode == C.FilterWhiteList {
		return !should
	}
	return should
}

func (p *Skipper) shouldSkipped(domain string) bool {
	for _, matcher := range p.Host {
		if matcher.MatchDomain(domain) {
			return true
		}
	}
	return false
}
