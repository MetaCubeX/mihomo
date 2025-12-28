package fakeip

import C "github.com/metacubex/mihomo/constant"

type FakeIPMode int

const (
	UseFakeIP FakeIPMode = iota
	UseRealIP
)

type FakeIPRule struct {
	Rule   C.Rule
	Action FakeIPMode
}

func (r *FakeIPRule) Match(domain string) bool {
	metadata := &C.Metadata{Host: domain}
	matched, _ := r.Rule.Match(metadata, C.RuleMatchHelper{})
	return matched
}

func (r *FakeIPRule) ShouldSkip() bool {
	return r.Action == UseRealIP
}
