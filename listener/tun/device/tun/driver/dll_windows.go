/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package driver

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/Dreamacro/clash/log"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
)

//go:linkname modwintun golang.zx2c4.com/wintun.modwintun

//go:linkname procWintunCreateAdapter golang.zx2c4.com/wintun.procWintunCreateAdapter

//go:linkname procWintunOpenAdapter golang.zx2c4.com/wintun.procWintunOpenAdapter

//go:linkname procWintunCloseAdapter golang.zx2c4.com/wintun.procWintunCloseAdapter

//go:linkname procWintunDeleteDriver golang.zx2c4.com/wintun.procWintunDeleteDriver

//go:linkname procWintunGetAdapterLUID golang.zx2c4.com/wintun.procWintunGetAdapterLUID

//go:linkname procWintunGetRunningDriverVersion golang.zx2c4.com/wintun.procWintunGetRunningDriverVersion

//go:linkname procWintunAllocateSendPacket golang.zx2c4.com/wintun.procWintunAllocateSendPacket

//go:linkname procWintunEndSession golang.zx2c4.com/wintun.procWintunEndSession

//go:linkname procWintunGetReadWaitEvent golang.zx2c4.com/wintun.procWintunGetReadWaitEvent

//go:linkname procWintunReceivePacket golang.zx2c4.com/wintun.procWintunReceivePacket

//go:linkname procWintunReleaseReceivePacket golang.zx2c4.com/wintun.procWintunReleaseReceivePacket

//go:linkname procWintunSendPacket golang.zx2c4.com/wintun.procWintunSendPacket

//go:linkname procWintunStartSession golang.zx2c4.com/wintun.procWintunStartSession

var (
	modwintun                         *lazyDLL
	procWintunCreateAdapter           *lazyProc
	procWintunOpenAdapter             *lazyProc
	procWintunCloseAdapter            *lazyProc
	procWintunDeleteDriver            *lazyProc
	procWintunGetAdapterLUID          *lazyProc
	procWintunGetRunningDriverVersion *lazyProc
	procWintunAllocateSendPacket      *lazyProc
	procWintunEndSession              *lazyProc
	procWintunGetReadWaitEvent        *lazyProc
	procWintunReceivePacket           *lazyProc
	procWintunReleaseReceivePacket    *lazyProc
	procWintunSendPacket              *lazyProc
	procWintunStartSession            *lazyProc
)

type loggerLevel int

const (
	logInfo loggerLevel = iota
	logWarn
	logErr
)

func init() {
	modwintun = newLazyDLL("wintun.dll", setupLogger)
	procWintunCreateAdapter = modwintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter = modwintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter = modwintun.NewProc("WintunCloseAdapter")
	procWintunDeleteDriver = modwintun.NewProc("WintunDeleteDriver")
	procWintunGetAdapterLUID = modwintun.NewProc("WintunGetAdapterLUID")
	procWintunGetRunningDriverVersion = modwintun.NewProc("WintunGetRunningDriverVersion")
	procWintunAllocateSendPacket = modwintun.NewProc("WintunAllocateSendPacket")
	procWintunEndSession = modwintun.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent = modwintun.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket = modwintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = modwintun.NewProc("WintunReleaseReceivePacket")
	procWintunSendPacket = modwintun.NewProc("WintunSendPacket")
	procWintunStartSession = modwintun.NewProc("WintunStartSession")
}

func InitWintun() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("init wintun.dll error: %v", r)
		}
	}()

	if err = modwintun.Load(); err != nil {
		return
	}

	procWintunCreateAdapter.Addr()
	procWintunOpenAdapter.Addr()
	procWintunCloseAdapter.Addr()
	procWintunDeleteDriver.Addr()
	procWintunGetAdapterLUID.Addr()
	procWintunGetRunningDriverVersion.Addr()
	procWintunAllocateSendPacket.Addr()
	procWintunEndSession.Addr()
	procWintunGetReadWaitEvent.Addr()
	procWintunReceivePacket.Addr()
	procWintunReleaseReceivePacket.Addr()
	procWintunSendPacket.Addr()
	procWintunStartSession.Addr()

	return
}

func newLazyDLL(name string, onLoad func(d *lazyDLL)) *lazyDLL {
	return &lazyDLL{Name: name, onLoad: onLoad}
}

func logMessage(level loggerLevel, _ uint64, msg *uint16) int {
	switch level {
	case logInfo:
		log.Infoln("[TUN] %s", windows.UTF16PtrToString(msg))
	case logWarn:
		log.Warnln("[TUN] %s", windows.UTF16PtrToString(msg))
	case logErr:
		log.Errorln("[TUN] %s", windows.UTF16PtrToString(msg))
	default:
		log.Debugln("[TUN] %s", windows.UTF16PtrToString(msg))
	}
	return 0
}

func setupLogger(dll *lazyDLL) {
	var callback uintptr
	if runtime.GOARCH == "386" {
		callback = windows.NewCallback(func(level loggerLevel, _, _ uint32, msg *uint16) int {
			return logMessage(level, 0, msg)
		})
	} else if runtime.GOARCH == "arm" {
		callback = windows.NewCallback(func(level loggerLevel, _, _, _ uint32, msg *uint16) int {
			return logMessage(level, 0, msg)
		})
	} else if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		callback = windows.NewCallback(logMessage)
	}
	_, _, _ = syscall.SyscallN(dll.NewProc("WintunSetLogger").Addr(), callback)
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
		return fmt.Errorf("error loading DLL: %s, MODULE: %s, error: %w", p.dll.Name, p.Name, err)
	}
	addr, err := p.nameToAddr()
	if err != nil {
		return fmt.Errorf("error getting %s address: %w", p.Name, err)
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

func (p *lazyProc) Load() error {
	return p.dll.Load()
}

type lazyDLL struct {
	Name   string
	Base   windows.Handle
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

	module, err := memmod.LoadLibrary(dllContent)
	if err != nil {
		return fmt.Errorf("unable to load library: %w", err)
	}
	d.Base = windows.Handle(module.BaseAddr())

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.module)), unsafe.Pointer(module))
	if d.onLoad != nil {
		d.onLoad(d)
	}
	return nil
}

func (p *lazyProc) nameToAddr() (uintptr, error) {
	return p.dll.module.ProcAddressByName(p.Name)
}
