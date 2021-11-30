/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"github.com/Dreamacro/clash/listener/tun/dev/wintun/embed_dll"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
	"sync"
	"sync/atomic"
	"unsafe"
)

func newLazyDLL(name string, onLoad func(d *lazyDLL)) *lazyDLL {
	return &lazyDLL{Name: name, onLoad: onLoad}
}

func (d *lazyDLL) NewProc(name string) *lazyProc {
	return &lazyProc{dll: d, Name: name}
}

type lazyProc struct {
	Name string
	mu   sync.Mutex
	dll  *lazyDLL
	addr uintptr
}

func (p *lazyProc) Find() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr))) != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addr != 0 {
		return nil
	}

	err := p.dll.Load()
	if err != nil {
		return fmt.Errorf("Error loading %v DLL: %w", p.dll.Name, err)
	}
	addr, err := p.nameToAddr()
	if err != nil {
		return fmt.Errorf("Error getting %v address: %w", p.Name, err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr)), unsafe.Pointer(addr))
	return nil
}

func (p *lazyProc) Addr() uintptr {
	err := p.Find()
	if err != nil {
		panic(err)
	}
	return p.addr
}

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

	module, err := memmod.LoadLibrary(embed_dll.DDlContent)
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
