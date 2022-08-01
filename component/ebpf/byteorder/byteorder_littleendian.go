//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package byteorder

import (
	"encoding/binary"
	"math/bits"
)

var Native binary.ByteOrder = binary.LittleEndian

func HostToNetwork16(u uint16) uint16 { return bits.ReverseBytes16(u) }
func HostToNetwork32(u uint32) uint32 { return bits.ReverseBytes32(u) }
func NetworkToHost16(u uint16) uint16 { return bits.ReverseBytes16(u) }
func NetworkToHost32(u uint32) uint32 { return bits.ReverseBytes32(u) }
