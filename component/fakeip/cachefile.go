package fakeip

import (
	"net"

	"github.com/Dreamacro/clash/component/profile/cachefile"
)

type cachefileStore struct {
	cache *cachefile.CacheFile
}

// GetByHost implements store.GetByHost
func (c *cachefileStore) GetByHost(host string) (net.IP, bool) {
	elm := c.cache.GetFakeip([]byte(host))
	if elm == nil {
		return nil, false
	}
	return net.IP(elm), true
}

// PutByHost implements store.PutByHost
func (c *cachefileStore) PutByHost(host string, ip net.IP) {
	c.cache.PutFakeip([]byte(host), ip)
}

// GetByIP implements store.GetByIP
func (c *cachefileStore) GetByIP(ip net.IP) (string, bool) {
	elm := c.cache.GetFakeip(ip.To4())
	if elm == nil {
		return "", false
	}
	return string(elm), true
}

// PutByIP implements store.PutByIP
func (c *cachefileStore) PutByIP(ip net.IP, host string) {
	c.cache.PutFakeip(ip.To4(), []byte(host))
}

// DelByIP implements store.DelByIP
func (c *cachefileStore) DelByIP(ip net.IP) {
	ip = ip.To4()
	c.cache.DelFakeipPair(ip, c.cache.GetFakeip(ip.To4()))
}

// Exist implements store.Exist
func (c *cachefileStore) Exist(ip net.IP) bool {
	_, exist := c.GetByIP(ip)
	return exist
}

// CloneTo implements store.CloneTo
// already persistence
func (c *cachefileStore) CloneTo(store store) {}
