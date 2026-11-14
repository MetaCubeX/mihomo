package socks

import (
	"net"
	"net/netip"
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

type associationEntry struct {
	user  string
	count int
}

var (
	associationMu sync.RWMutex
	associations  = make(map[netip.Addr]*associationEntry)
)

func addAssociation(peer netip.Addr, user string) {
	associationMu.Lock()
	defer associationMu.Unlock()

	if entry, ok := associations[peer]; ok {
		entry.user = user
		entry.count++
		return
	}
	associations[peer] = &associationEntry{user: user, count: 1}
}

func removeAssociation(peer netip.Addr) {
	associationMu.Lock()
	defer associationMu.Unlock()

	entry, ok := associations[peer]
	if !ok {
		return
	}
	if entry.count--; entry.count <= 0 {
		delete(associations, peer)
	}
}

func lookupAssociation(peer netip.Addr) (string, bool) {
	associationMu.RLock()
	defer associationMu.RUnlock()

	entry, ok := associations[peer]
	if !ok {
		return "", false
	}
	return entry.user, true
}

func addrOf(addr net.Addr) (netip.Addr, bool) {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return netip.Addr{}, false
	}
	ip := m.AddrPort().Addr()
	if !ip.IsValid() {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
