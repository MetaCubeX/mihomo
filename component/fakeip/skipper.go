package fakeip

import (
	C "github.com/metacubex/mihomo/constant"
)

type Skipper struct {
	Rules       []*FakeIPRule
	DefaultMode FakeIPMode

	Host []C.DomainMatcher
	Mode C.FilterMode
}

// ShouldSkipped return if domain should be skipped
func (p *Skipper) ShouldSkipped(domain string) bool {
	if len(p.Rules) > 0 {
		for _, rule := range p.Rules {
			if rule.Match(domain) {
				return rule.ShouldSkip()
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
