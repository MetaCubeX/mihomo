package dns

import (
	"net/netip"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/fakeip"
	C "github.com/metacubex/mihomo/constant"
)

type ResolverEnhancer struct {
	mode     C.DNSMode
	fakePool *fakeip.Pool
	mapping  *lru.LruCache[netip.Addr, string]
}

func (h *ResolverEnhancer) FakeIPEnabled() bool {
	return h.mode == C.DNSFakeIP
}

func (h *ResolverEnhancer) MappingEnabled() bool {
	return h.mode == C.DNSFakeIP || h.mode == C.DNSMapping
}

func (h *ResolverEnhancer) IsExistFakeIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.Exist(ip)
	}

	return false
}

func (h *ResolverEnhancer) IsFakeIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.IPNet().Contains(ip) && ip != pool.Gateway() && ip != pool.Broadcast()
	}

	return false
}

func (h *ResolverEnhancer) IsFakeBroadcastIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.Broadcast() == ip
	}

	return false
}

func (h *ResolverEnhancer) FindHostByIP(ip netip.Addr) (string, bool) {
	if pool := h.fakePool; pool != nil {
		if host, existed := pool.LookBack(ip); existed {
			return host, true
		}
	}

	if mapping := h.mapping; mapping != nil {
		if host, existed := h.mapping.Get(ip); existed {
			return host, true
		}
	}

	return "", false
}

func (h *ResolverEnhancer) InsertHostByIP(ip netip.Addr, host string) {
	if mapping := h.mapping; mapping != nil {
		h.mapping.Set(ip, host)
	}
}

func (h *ResolverEnhancer) FlushFakeIP() error {
	if h.fakePool != nil {
		return h.fakePool.FlushFakeIP()
	}
	return nil
}

func (h *ResolverEnhancer) PatchFrom(o *ResolverEnhancer) {
	if h.mapping != nil && o.mapping != nil {
		o.mapping.CloneTo(h.mapping)
	}

	if h.fakePool != nil && o.fakePool != nil {
		h.fakePool.CloneFrom(o.fakePool)
	}
}

func (h *ResolverEnhancer) StoreFakePoolState() {
	if h.fakePool != nil {
		h.fakePool.StoreState()
	}
}

func NewEnhancer(cfg Config) *ResolverEnhancer {
	var fakePool *fakeip.Pool
	var mapping *lru.LruCache[netip.Addr, string]

	if cfg.EnhancedMode != C.DNSNormal {
		fakePool = cfg.Pool
		mapping = lru.New(lru.WithSize[netip.Addr, string](4096))
	}

	return &ResolverEnhancer{
		mode:     cfg.EnhancedMode,
		fakePool: fakePool,
		mapping:  mapping,
	}
}
