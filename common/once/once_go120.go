//go:build !go1.22

package once

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

type Once struct {
	done uint32
	m    sync.Mutex
}

func Done(once *sync.Once) bool {
	// atomic visit sync.Once.done
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(once))) == 1
}

func Reset(once *sync.Once) {
	o := (*Once)(unsafe.Pointer(once))
	o.m.Lock()
	defer o.m.Unlock()
	atomic.StoreUint32(&o.done, 0)
}
