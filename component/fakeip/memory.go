package fakeip

import (
	"net/netip"

	"github.com/metacubex/mihomo/common/lru"
)

type memoryStore struct {
	cacheIP   *lru.LruCache[string, netip.Addr]
	cacheHost *lru.LruCache[netip.Addr, string]
}

// GetByHost implements store.GetByHost
func (m *memoryStore) GetByHost(host string) (netip.Addr, bool) {
	if ip, exist := m.cacheIP.Get(host); exist {
		// ensure ip --> host on head of linked list
		m.cacheHost.Get(ip)
		return ip, true
	}

	return netip.Addr{}, false
}

// PutByHost implements store.PutByHost
func (m *memoryStore) PutByHost(host string, ip netip.Addr) {
	m.cacheIP.Set(host, ip)
}

// GetByIP implements store.GetByIP
func (m *memoryStore) GetByIP(ip netip.Addr) (string, bool) {
	if host, exist := m.cacheHost.Get(ip); exist {
		// ensure host --> ip on head of linked list
		m.cacheIP.Get(host)
		return host, true
	}

	return "", false
}

// PutByIP implements store.PutByIP
func (m *memoryStore) PutByIP(ip netip.Addr, host string) {
	m.cacheHost.Set(ip, host)
}

// DelByIP implements store.DelByIP
func (m *memoryStore) DelByIP(ip netip.Addr) {
	if host, exist := m.cacheHost.Get(ip); exist {
		m.cacheIP.Delete(host)
	}
	m.cacheHost.Delete(ip)
}

// Exist implements store.Exist
func (m *memoryStore) Exist(ip netip.Addr) bool {
	return m.cacheHost.Exist(ip)
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
	m.cacheIP.Clear()
	m.cacheHost.Clear()
	return nil
}

func newMemoryStore(size int) *memoryStore {
	return &memoryStore{
		cacheIP:   lru.New[string, netip.Addr](lru.WithSize[string, netip.Addr](size)),
		cacheHost: lru.New[netip.Addr, string](lru.WithSize[netip.Addr, string](size)),
	}
}
