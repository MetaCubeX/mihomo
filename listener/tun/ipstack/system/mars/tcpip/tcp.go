package tcpip

import (
	"encoding/binary"
	"net"
)

const (
	TCPFin uint16 = 1 << 0
	TCPSyn uint16 = 1 << 1
	TCPRst uint16 = 1 << 2
	TCPPuh uint16 = 1 << 3
	TCPAck uint16 = 1 << 4
	TCPUrg uint16 = 1 << 5
	TCPEce uint16 = 1 << 6
	TCPEwr uint16 = 1 << 7
	TCPNs  uint16 = 1 << 8
)

const TCPHeaderSize = 20

type TCPPacket []byte

func (p TCPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p TCPPacket) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(p, port)
}

func (p TCPPacket) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p TCPPacket) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(p[2:], port)
}

func (p TCPPacket) Flags() uint16 {
	return uint16(p[13] | (p[12] & 0x1))
}

func (p TCPPacket) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[16:])
}

func (p TCPPacket) SetChecksum(sum [2]byte) {
	p[16] = sum[0]
	p[17] = sum[1]
}

func (p TCPPacket) ResetChecksum(psum uint32) {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(psum, p))
}

func (p TCPPacket) Valid() bool {
	return len(p) >= TCPHeaderSize
}

func (p TCPPacket) Verify(sourceAddress net.IP, targetAddress net.IP) error {
	var checksum [2]byte
	checksum[0] = p[16]
	checksum[1] = p[17]

	// reset checksum
	p[16] = 0
	p[17] = 0

	// restore checksum
	defer func() {
		p[16] = checksum[0]
		p[17] = checksum[1]
	}()

	// check checksum
	s := uint32(0)
	s += Sum(sourceAddress)
	s += Sum(targetAddress)
	s += uint32(TCP)
	s += uint32(len(p))

	check := Checksum(s, p)
	if checksum[0] != check[0] || checksum[1] != check[1] {
		return ErrInvalidChecksum
	}

	return nil
}
