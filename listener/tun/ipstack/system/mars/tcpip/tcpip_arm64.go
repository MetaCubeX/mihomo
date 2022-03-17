package tcpip

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

//go:noescape
func sumAsmNeon(data unsafe.Pointer, length uintptr) uintptr

func SumNeon(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}

	return uint32(sumAsmNeon(unsafe.Pointer(&data[0]), uintptr(len(data))))
}

func init() {
	if cpu.ARM64.HasASIMD {
		SumFnc = SumNeon
	}
}
