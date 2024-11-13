package nat

import (
	"net"
	"sync"

	C "github.com/metacubex/mihomo/constant"

	"github.com/puzpuzpuz/xsync/v3"
)

type Table struct {
	mapping *xsync.MapOf[string, *entry]
}

type entry struct {
	PacketSender    C.PacketSender
	LocalUDPConnMap *xsync.MapOf[string, *net.UDPConn]
	LocalLockMap    *xsync.MapOf[string, *sync.Cond]
}

func (t *Table) GetOrCreate(key string, maker func() C.PacketSender) (C.PacketSender, bool) {
	item, loaded := t.mapping.LoadOrCompute(key, func() *entry {
		return &entry{
			PacketSender:    maker(),
			LocalUDPConnMap: xsync.NewMapOf[string, *net.UDPConn](),
			LocalLockMap:    xsync.NewMapOf[string, *sync.Cond](),
		}
	})
	return item.PacketSender, loaded
}

func (t *Table) Delete(key string) {
	t.mapping.Delete(key)
}

func (t *Table) GetForLocalConn(lAddr, rAddr string) *net.UDPConn {
	entry, exist := t.getEntry(lAddr)
	if !exist {
		return nil
	}
	item, exist := entry.LocalUDPConnMap.Load(rAddr)
	if !exist {
		return nil
	}
	return item
}

func (t *Table) AddForLocalConn(lAddr, rAddr string, conn *net.UDPConn) bool {
	entry, exist := t.getEntry(lAddr)
	if !exist {
		return false
	}
	entry.LocalUDPConnMap.Store(rAddr, conn)
	return true
}

func (t *Table) RangeForLocalConn(lAddr string, f func(key string, value *net.UDPConn) bool) {
	entry, exist := t.getEntry(lAddr)
	if !exist {
		return
	}
	entry.LocalUDPConnMap.Range(f)
}

func (t *Table) GetOrCreateLockForLocalConn(lAddr, key string) (*sync.Cond, bool) {
	entry, loaded := t.getEntry(lAddr)
	if !loaded {
		return nil, false
	}
	item, loaded := entry.LocalLockMap.LoadOrCompute(key, makeLock)
	return item, loaded
}

func (t *Table) DeleteForLocalConn(lAddr, key string) {
	entry, loaded := t.getEntry(lAddr)
	if !loaded {
		return
	}
	entry.LocalUDPConnMap.Delete(key)
}

func (t *Table) DeleteLockForLocalConn(lAddr, key string) {
	entry, loaded := t.getEntry(lAddr)
	if !loaded {
		return
	}
	entry.LocalLockMap.Delete(key)
}

func (t *Table) getEntry(key string) (*entry, bool) {
	return t.mapping.Load(key)
}

func makeLock() *sync.Cond {
	return sync.NewCond(&sync.Mutex{})
}

// New return *Cache
func New() *Table {
	return &Table{
		mapping: xsync.NewMapOf[string, *entry](),
	}
}
