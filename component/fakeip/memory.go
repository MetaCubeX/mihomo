package fakeip

import (
	"net"

	"github.com/Dreamacro/clash/common/cache"
)

type memoryStore struct {
	cacheIP   *cache.LruCache[string, net.IP]
	cacheHost *cache.LruCache[uint32, string]
}

// GetByHost implements store.GetByHost
func (m *memoryStore) GetByHost(host string) (net.IP, bool) {
	if ip, exist := m.cacheIP.Get(host); exist {
		// ensure ip --> host on head of linked list
		m.cacheHost.Get(ipToUint(ip.To4()))
		return ip, true
	}

	return nil, false
}

// PutByHost implements store.PutByHost
func (m *memoryStore) PutByHost(host string, ip net.IP) {
	m.cacheIP.Set(host, ip)
}

// GetByIP implements store.GetByIP
func (m *memoryStore) GetByIP(ip net.IP) (string, bool) {
	if host, exist := m.cacheHost.Get(ipToUint(ip.To4())); exist {
		// ensure host --> ip on head of linked list
		m.cacheIP.Get(host)
		return host, true
	}

	return "", false
}

// PutByIP implements store.PutByIP
func (m *memoryStore) PutByIP(ip net.IP, host string) {
	m.cacheHost.Set(ipToUint(ip.To4()), host)
}

// DelByIP implements store.DelByIP
func (m *memoryStore) DelByIP(ip net.IP) {
	ipNum := ipToUint(ip.To4())
	if host, exist := m.cacheHost.Get(ipNum); exist {
		m.cacheIP.Delete(host)
	}
	m.cacheHost.Delete(ipNum)
}

// Exist implements store.Exist
func (m *memoryStore) Exist(ip net.IP) bool {
	return m.cacheHost.Exist(ipToUint(ip.To4()))
}

// CloneTo implements store.CloneTo
// only for memoryStore to memoryStore
func (m *memoryStore) CloneTo(store store) {
	if ms, ok := store.(*memoryStore); ok {
		m.cacheIP.CloneTo(ms.cacheIP)
		m.cacheHost.CloneTo(ms.cacheHost)
	}
}

// FlushFakeIP implements store.FlushFakeIP
func (m *memoryStore) FlushFakeIP() error {
	_ = m.cacheIP.Clear()
	return m.cacheHost.Clear()
}

func newMemoryStore(size int) *memoryStore {
	return &memoryStore{
		cacheIP:   cache.NewLRUCache[string, net.IP](cache.WithSize[string, net.IP](size)),
		cacheHost: cache.NewLRUCache[uint32, string](cache.WithSize[uint32, string](size)),
	}
}
