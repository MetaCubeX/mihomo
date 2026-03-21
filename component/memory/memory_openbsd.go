package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	CTLKern     = 1
	KernProc    = 14
	KernProcPID = 1
)

func callKernProcSyscall(op int32, arg int32) ([]byte, uint64, error) {
	mib := []int32{CTLKern, KernProc, op, arg, sizeOfKinfoProc, 0}
	mibptr := unsafe.Pointer(&mib[0])
	miblen := uint64(len(mib))
	length := uint64(0)
	_, _, err := unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(mibptr),
		uintptr(miblen),
		0,
		uintptr(unsafe.Pointer(&length)),
		0,
		0)
	if err != 0 {
		return nil, length, err
	}

	count := int32(length / uint64(sizeOfKinfoProc))
	mib = []int32{CTLKern, KernProc, op, arg, sizeOfKinfoProc, count}
	mibptr = unsafe.Pointer(&mib[0])
	miblen = uint64(len(mib))
	// get proc info itself
	buf := make([]byte, length)
	_, _, err = unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(mibptr),
		uintptr(miblen),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&length)),
		0,
		0)
	if err != 0 {
		return buf, length, err
	}

	return buf, length, nil
}

func parseKinfoProc(buf []byte) (KinfoProc, error) {
	var k KinfoProc
	br := bytes.NewReader(buf)
	err := binary.Read(br, binary.LittleEndian, &k)
	return k, err
}

func getKProc(pid int32) (*KinfoProc, error) {
	buf, length, err := callKernProcSyscall(KernProcPID, pid)
	if err != nil {
		return nil, err
	}
	if length != sizeOfKinfoProc {
		return nil, errors.New("unexpected size of KinfoProc")
	}

	k, err := parseKinfoProc(buf)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func GetMemoryInfo(pid int32) (*MemoryInfoStat, error) {
	k, err := getKProc(pid)
	if err != nil {
		return nil, err
	}
	uvmexp, err := unix.SysctlUvmexp("vm.uvmexp")
	if err != nil {
		return nil, err
	}
	pageSize := uint64(uvmexp.Pagesize)

	return &MemoryInfoStat{
		RSS: uint64(k.Vm_rssize) * pageSize,
		VMS: uint64(k.Vm_tsize) + uint64(k.Vm_dsize) +
			uint64(k.Vm_ssize),
	}, nil
}
