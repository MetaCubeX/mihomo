package dns

import (
	"net"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/fakeip"
	C "github.com/Dreamacro/clash/constant"
)

type ResolverEnhancer struct {
	mode     C.DNSMode
	fakePool *fakeip.Pool
	mapping  *cache.LruCache
}

func (h *ResolverEnhancer) FakeIPEnabled() bool {
	return h.mode == C.DNSFakeIP
}

func (h *ResolverEnhancer) MappingEnabled() bool {
	return h.mode == C.DNSFakeIP || h.mode == C.DNSMapping
}

func (h *ResolverEnhancer) IsExistFakeIP(ip net.IP) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.Exist(ip)
	}

	return false
}

func (h *ResolverEnhancer) IsFakeIP(ip net.IP) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.IPNet().Contains(ip) && !pool.Gateway().Equal(ip)
	}

	return false
}

func (h *ResolverEnhancer) FindHostByIP(ip net.IP) (string, bool) {
	if pool := h.fakePool; pool != nil {
		if host, existed := pool.LookBack(ip); existed {
			return host, true
		}
	}

	if mapping := h.mapping; mapping != nil {
		if host, existed := h.mapping.Get(ip.String()); existed {
			return host.(string), true
		}
	}

	return "", false
}

func (h *ResolverEnhancer) PatchFrom(o *ResolverEnhancer) {
	if h.mapping != nil && o.mapping != nil {
		o.mapping.CloneTo(h.mapping)
	}

	if h.fakePool != nil && o.fakePool != nil {
		h.fakePool.CloneFrom(o.fakePool)
	}
}

func NewEnhancer(cfg Config) *ResolverEnhancer {
	var fakePool *fakeip.Pool
	var mapping *cache.LruCache

	if cfg.EnhancedMode != C.DNSNormal {
		fakePool = cfg.Pool
		mapping = cache.New(cache.WithSize(4096), cache.WithStale(true))
	}

	return &ResolverEnhancer{
		mode:     cfg.EnhancedMode,
		fakePool: fakePool,
		mapping:  mapping,
	}
}
