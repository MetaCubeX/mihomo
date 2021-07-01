// +build !load_wintun_from_rsrc

package wintun

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

type lazyDLL struct {
	Name   string
	mu     sync.Mutex
	module windows.Handle
	onLoad func(d *lazyDLL)
}

func (d *lazyDLL) Load() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.module))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module != 0 {
		return nil
	}

	const (
		LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200
		LOAD_LIBRARY_SEARCH_SYSTEM32        = 0x00000800
	)
	module, err := windows.LoadLibraryEx(d.Name, 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return fmt.Errorf("Unable to load library: %w", err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.module)), unsafe.Pointer(module))
	if d.onLoad != nil {
		d.onLoad(d)
	}
	return nil
}

func (p *lazyProc) nameToAddr() (uintptr, error) {
	return windows.GetProcAddress(p.dll.module, p.Name)
}
