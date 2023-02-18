package nat

import (
	"net"
	"sync"

	C "github.com/Dreamacro/clash/constant"
)

type Table struct {
	mapping sync.Map
}

type Entry struct {
	PacketConn      C.PacketConn
	LocalUDPConnMap sync.Map
}

func (t *Table) Set(key string, e C.PacketConn) {
	t.mapping.Store(key, &Entry{
		PacketConn:      e,
		LocalUDPConnMap: sync.Map{},
	})
}

func (t *Table) Get(key string) C.PacketConn {
	entry, exist := t.getEntry(key)
	if !exist {
		return nil
	}
	return entry.PacketConn
}

func (t *Table) GetOrCreateLock(key string) (*sync.Cond, bool) {
	item, loaded := t.mapping.LoadOrStore(key, sync.NewCond(&sync.Mutex{}))
	return item.(*sync.Cond), loaded
}

func (t *Table) Delete(key string) {
	t.mapping.Delete(key)
}

func (t *Table) GetLocalConn(lAddr, rAddr string) *net.UDPConn {
	entry, exist := t.getEntry(lAddr)
	if !exist {
		return nil
	}
	item, exist := entry.LocalUDPConnMap.Load(rAddr)
	if !exist {
		return nil
	}
	return item.(*net.UDPConn)
}

func (t *Table) AddLocalConn(lAddr, rAddr string, conn *net.UDPConn) bool {
	entry, exist := t.getEntry(lAddr)
	if !exist {
		return false
	}
	entry.LocalUDPConnMap.Store(rAddr, conn)
	return true
}

func (t *Table) RangeLocalConn(lAddr string, f func(key, value any) bool) {
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
	item, loaded := entry.LocalUDPConnMap.LoadOrStore(key, sync.NewCond(&sync.Mutex{}))
	return item.(*sync.Cond), loaded
}

func (t *Table) DeleteLocalConnMap(lAddr, key string) {
	entry, loaded := t.getEntry(lAddr)
	if !loaded {
		return
	}
	entry.LocalUDPConnMap.Delete(key)
}

func (t *Table) getEntry(key string) (*Entry, bool) {
	item, ok := t.mapping.Load(key)
	// This should not happen usually since this function called after PacketConn created
	if !ok {
		return nil, false
	}
	entry, ok := item.(*Entry)
	return entry, ok
}

// New return *Cache
func New() *Table {
	return &Table{}
}
