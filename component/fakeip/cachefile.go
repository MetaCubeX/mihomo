package fakeip

import (
	"net/netip"

	"github.com/metacubex/mihomo/component/profile/cachefile"
)

type cachefileStore struct {
	cache *cachefile.FakeIpStore
}

// GetByHost implements store.GetByHost
func (c *cachefileStore) GetByHost(host string) (netip.Addr, bool) {
	return c.cache.GetByHost(host)
}

// PutByHost implements store.PutByHost
func (c *cachefileStore) PutByHost(host string, ip netip.Addr) {
	c.cache.PutByHost(host, ip)
}

// GetByIP implements store.GetByIP
func (c *cachefileStore) GetByIP(ip netip.Addr) (string, bool) {
	return c.cache.GetByIP(ip)
}

// PutByIP implements store.PutByIP
func (c *cachefileStore) PutByIP(ip netip.Addr, host string) {
	c.cache.PutByIP(ip, host)
}

// DelByIP implements store.DelByIP
func (c *cachefileStore) DelByIP(ip netip.Addr) {
	c.cache.DelByIP(ip)
}

// Exist implements store.Exist
func (c *cachefileStore) Exist(ip netip.Addr) bool {
	_, exist := c.GetByIP(ip)
	return exist
}

// CloneTo implements store.CloneTo
// already persistence
func (c *cachefileStore) CloneTo(store store) {}

// FlushFakeIP implements store.FlushFakeIP
func (c *cachefileStore) FlushFakeIP() error {
	return c.cache.FlushFakeIP()
}

func newCachefileStore(cache *cachefile.CacheFile) *cachefileStore {
	return &cachefileStore{cache.FakeIpStore()}
}
