package fakeip

import (
	"net/netip"

	"github.com/metacubex/mihomo/component/profile/cachefile"
)

type cachefileStore struct {
	cache *cachefile.CacheFile
}

// GetByHost implements store.GetByHost
func (c *cachefileStore) GetByHost(host string) (netip.Addr, bool) {
	elm := c.cache.GetFakeip([]byte(host))
	if elm == nil {
		return netip.Addr{}, false
	}

	if len(elm) == 4 {
		return netip.AddrFrom4(*(*[4]byte)(elm)), true
	} else {
		return netip.AddrFrom16(*(*[16]byte)(elm)), true
	}
}

// PutByHost implements store.PutByHost
func (c *cachefileStore) PutByHost(host string, ip netip.Addr) {
	c.cache.PutFakeip([]byte(host), ip.AsSlice())
}

// GetByIP implements store.GetByIP
func (c *cachefileStore) GetByIP(ip netip.Addr) (string, bool) {
	elm := c.cache.GetFakeip(ip.AsSlice())
	if elm == nil {
		return "", false
	}
	return string(elm), true
}

// PutByIP implements store.PutByIP
func (c *cachefileStore) PutByIP(ip netip.Addr, host string) {
	c.cache.PutFakeip(ip.AsSlice(), []byte(host))
}

// DelByIP implements store.DelByIP
func (c *cachefileStore) DelByIP(ip netip.Addr) {
	addr := ip.AsSlice()
	c.cache.DelFakeipPair(addr, c.cache.GetFakeip(addr))
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
