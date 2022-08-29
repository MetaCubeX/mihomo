//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package byteorder

import "encoding/binary"

var Native binary.ByteOrder = binary.BigEndian

func HostToNetwork16(u uint16) uint16 { return u }
func HostToNetwork32(u uint32) uint32 { return u }
func NetworkToHost16(u uint16) uint16 { return u }
func NetworkToHost32(u uint32) uint32 { return u }
