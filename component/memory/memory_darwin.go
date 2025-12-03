package memory

import (
	"syscall"
	"unsafe"
	_ "unsafe"
)

const PROC_PIDTASKINFO = 4

type ProcTaskInfo struct {
	Virtual_size      uint64
	Resident_size     uint64
	Total_user        uint64
	Total_system      uint64
	Threads_user      uint64
	Threads_system    uint64
	Policy            int32
	Faults            int32
	Pageins           int32
	Cow_faults        int32
	Messages_sent     int32
	Messages_received int32
	Syscalls_mach     int32
	Syscalls_unix     int32
	Csw               int32
	Threadnum         int32
	Numrunning        int32
	Priority          int32
}

func GetMemoryInfo(pid int32) (*MemoryInfoStat, error) {
	var ti ProcTaskInfo
	_, _, errno := syscall_syscall6(proc_pidinfo_trampoline_addr, uintptr(pid), PROC_PIDTASKINFO, 0, uintptr(unsafe.Pointer(&ti)), unsafe.Sizeof(ti), 0)
	if errno != 0 {
		return nil, errno
	}

	ret := &MemoryInfoStat{
		RSS: uint64(ti.Resident_size),
		VMS: uint64(ti.Virtual_size),
	}
	return ret, nil
}

var proc_pidinfo_trampoline_addr uintptr

//go:cgo_import_dynamic proc_pidinfo proc_pidinfo "/usr/lib/libSystem.B.dylib"

// from golang.org/x/sys@v0.30.0/unix/syscall_darwin_libSystem.go

// Implemented in the runtime package (runtime/sys_darwin.go)
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscall6X(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno) // 32-bit only
func syscall_rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_rawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscallPtr(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall_syscall syscall.syscall
//go:linkname syscall_syscall6 syscall.syscall6
//go:linkname syscall_syscall6X syscall.syscall6X
//go:linkname syscall_syscall9 syscall.syscall9
//go:linkname syscall_rawSyscall syscall.rawSyscall
//go:linkname syscall_rawSyscall6 syscall.rawSyscall6
//go:linkname syscall_syscallPtr syscall.syscallPtr
