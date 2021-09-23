//go:build load_wintun_from_rsrc
// +build load_wintun_from_rsrc

package wintun

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Dreamacro/clash/listener/tun/dev/wintun/memmod"
)

type lazyDLL struct {
	Name   string
	mu     sync.Mutex
	module *memmod.Module
	onLoad func(d *lazyDLL)
}

func (d *lazyDLL) Load() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.module))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module != nil {
		return nil
	}

	const ourModule windows.Handle = 0
	resInfo, err := windows.FindResource(ourModule, d.Name, windows.RT_RCDATA)
	if err != nil {
		return fmt.Errorf("Unable to find \"%v\" RCDATA resource: %w", d.Name, err)
	}
	data, err := windows.LoadResourceData(ourModule, resInfo)
	if err != nil {
		return fmt.Errorf("Unable to load resource: %w", err)
	}
	module, err := memmod.LoadLibrary(data)
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
	return p.dll.module.ProcAddressByName(p.Name)
}
