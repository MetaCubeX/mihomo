package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	CTLKern          = 1
	KernProc         = 14
	KernProcPID      = 1
)

func CallSyscall(mib []int32) ([]byte, uint64, error) {
	mibptr := unsafe.Pointer(&mib[0])
	miblen := uint64(len(mib))

	// get required buffer size
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
		var b []byte
		return b, length, err
	}
	if length == 0 {
		var b []byte
		return b, length, err
	}
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
	mib := []int32{CTLKern, KernProc, KernProcPID, pid}

	buf, length, err := CallSyscall(mib)
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
	v, err := unix.Sysctl("vm.stats.vm.v_page_size")
	if err != nil {
		return nil, err
	}
	pageSize := binary.LittleEndian.Uint16([]byte(v))

	return &MemoryInfoStat{
		RSS: uint64(k.Rssize) * uint64(pageSize),
		VMS: uint64(k.Size),
	}, nil
}
