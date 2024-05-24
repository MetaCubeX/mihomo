package common

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/domain"
	P "path"
)

var sets map[string]*domain.DomainSet = make(map[string]*domain.DomainSet)

type FileDI struct {
	adapter string
	payload string
}

func (f *FileDI) RuleType() C.RuleType {
	return C.FileDI
}

func (f *FileDI) Match(metadata *C.Metadata) (bool, string) {
	zoneset, ok := sets[f.payload]
	if !ok {
		return false, f.adapter
	}
	host := metadata.Host
	if host == "" {
		return false, f.adapter
	}
	if zoneset.HasDomain(host) {
		return true, f.adapter
	}
	return false, f.adapter
}

func (f *FileDI) Adapter() string {
	return f.adapter
}

func (f *FileDI) Payload() string {
	return f.payload
}

func (f *FileDI) ShouldResolveIP() bool {
	return false
}

func (f *FileDI) ShouldFindProcess() bool {
	return false
}

// FILEDI,alias,DIRECT,file path
func NewFileDi(payload, adapter, file string) *FileDI {
	domainSet := &domain.DomainSet{
		File:    P.Join(C.Path.HomeDir(), file),
		Payload: payload,
	}
	domainSet.Init()
	sets[payload] = domainSet
	return &FileDI{
		adapter: adapter,
		payload: payload,
	}
}
