package nat

import (
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
)

type Table struct {
	mapping xsync.Map[string, *entry]
}

type entry struct {
	PacketSender    C.PacketSender
	LocalUDPConnMap xsync.Map[string, *net.UDPConn]
	LocalLockMap    xsync.Map[string, *sync.Cond]
}

func (t *Table) GetOrCreate(key string, maker func() C.PacketSender) (C.PacketSender, bool) {
	item, loaded := t.mapping.LoadOrStoreFn(key, func() *entry {
		return &entry{
			PacketSender: maker(),
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
	item, loaded := entry.LocalLockMap.LoadOrStoreFn(key, makeLock)
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
	return &Table{}
}
