//go:build go1.22

package once

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

type Once struct {
	done atomic.Uint32
	m    sync.Mutex
}

func Done(once *sync.Once) bool {
	// atomic visit sync.Once.done
	return (*atomic.Uint32)(unsafe.Pointer(once)).Load() == 1
}

func Reset(once *sync.Once) {
	o := (*Once)(unsafe.Pointer(once))
	o.m.Lock()
	defer o.m.Unlock()
	o.done.Store(0)
}
