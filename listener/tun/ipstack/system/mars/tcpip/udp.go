package tcpip

import (
	"encoding/binary"
)

const UDPHeaderSize = 8

type UDPPacket []byte

func (p UDPPacket) Length() uint16 {
	return binary.BigEndian.Uint16(p[4:])
}

func (p UDPPacket) SetLength(length uint16) {
	binary.BigEndian.PutUint16(p[4:], length)
}

func (p UDPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p UDPPacket) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(p, port)
}

func (p UDPPacket) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p UDPPacket) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(p[2:], port)
}

func (p UDPPacket) Payload() []byte {
	return p[UDPHeaderSize:p.Length()]
}

func (p UDPPacket) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[6:])
}

func (p UDPPacket) SetChecksum(sum [2]byte) {
	p[6] = sum[0]
	p[7] = sum[1]
}

func (p UDPPacket) ResetChecksum(psum uint32) {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(psum, p))
}

func (p UDPPacket) Valid() bool {
	return len(p) >= UDPHeaderSize && uint16(len(p)) >= p.Length()
}
