package tcpip

import (
	"encoding/binary"
)

type ICMPType = byte

const (
	ICMPTypePingRequest  byte = 0x8
	ICMPTypePingResponse byte = 0x0
)

type ICMPPacket []byte

func (p ICMPPacket) Type() ICMPType {
	return p[0]
}

func (p ICMPPacket) SetType(v ICMPType) {
	p[0] = v
}

func (p ICMPPacket) Code() byte {
	return p[1]
}

func (p ICMPPacket) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p ICMPPacket) SetChecksum(sum [2]byte) {
	p[2] = sum[0]
	p[3] = sum[1]
}

func (p ICMPPacket) ResetChecksum() {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(0, p))
}
