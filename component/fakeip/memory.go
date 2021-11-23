package fakeip

import (
	"net"

	"github.com/Dreamacro/clash/common/cache"
)

type memoryStore struct {
	cache *cache.LruCache
}

// GetByHost implements store.GetByHost
func (m *memoryStore) GetByHost(host string) (net.IP, bool) {
	if elm, exist := m.cache.Get(host); exist {
		ip := elm.(net.IP)

		// ensure ip --> host on head of linked list
		m.cache.Get(ipToUint(ip.To4()))
		return ip, true
	}

	return nil, false
}

// PutByHost implements store.PutByHost
func (m *memoryStore) PutByHost(host string, ip net.IP) {
	m.cache.Set(host, ip)
}

// GetByIP implements store.GetByIP
func (m *memoryStore) GetByIP(ip net.IP) (string, bool) {
	if elm, exist := m.cache.Get(ipToUint(ip.To4())); exist {
		host := elm.(string)

		// ensure host --> ip on head of linked list
		m.cache.Get(host)
		return host, true
	}

	return "", false
}

// PutByIP implements store.PutByIP
func (m *memoryStore) PutByIP(ip net.IP, host string) {
	m.cache.Set(ipToUint(ip.To4()), host)
}

// DelByIP implements store.DelByIP
func (m *memoryStore) DelByIP(ip net.IP) {
	ipNum := ipToUint(ip.To4())
	if elm, exist := m.cache.Get(ipNum); exist {
		m.cache.Delete(elm.(string))
	}
	m.cache.Delete(ipNum)
}

// Exist implements store.Exist
func (m *memoryStore) Exist(ip net.IP) bool {
	return m.cache.Exist(ipToUint(ip.To4()))
}

// CloneTo implements store.CloneTo
// only for memoryStore to memoryStore
func (m *memoryStore) CloneTo(store store) {
	if ms, ok := store.(*memoryStore); ok {
		m.cache.CloneTo(ms.cache)
	}
}
