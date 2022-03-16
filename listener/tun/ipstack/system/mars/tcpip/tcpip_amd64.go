//go:build !noasm

package tcpip

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

//go:noescape
func sumAsmAvx2(data unsafe.Pointer, length uintptr) uintptr

func SumAVX2(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}

	return uint32(sumAsmAvx2(unsafe.Pointer(&data[0]), uintptr(len(data))))
}

func init() {
	if cpu.X86.HasAVX2 {
		SumFnc = SumAVX2
	}
}
