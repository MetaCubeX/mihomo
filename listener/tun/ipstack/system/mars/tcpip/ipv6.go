package tcpip

import (
	"encoding/binary"
	"net/netip"
)

const (
	versTCFL = 0

	IPv6PayloadLenOffset = 4

	IPv6NextHeaderOffset = 6
	hopLimit             = 7
	v6SrcAddr            = 8
	v6DstAddr            = v6SrcAddr + IPv6AddressSize

	IPv6FixedHeaderSize = v6DstAddr + IPv6AddressSize
)

const (
	versIHL        = 0
	tos            = 1
	ipVersionShift = 4
	ipIHLMask      = 0x0f
	IPv4IHLStride  = 4
)

type IPv6Packet []byte

const (
	IPv6MinimumSize = IPv6FixedHeaderSize

	IPv6AddressSize = 16

	IPv6Version = 6

	IPv6MinimumMTU = 1280
)

func (b IPv6Packet) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv6PayloadLenOffset:])
}

func (b IPv6Packet) HopLimit() uint8 {
	return b[hopLimit]
}

func (b IPv6Packet) NextHeader() byte {
	return b[IPv6NextHeaderOffset]
}

func (b IPv6Packet) Protocol() IPProtocol {
	return b.NextHeader()
}

func (b IPv6Packet) Payload() []byte {
	return b[IPv6MinimumSize:][:b.PayloadLength()]
}

func (b IPv6Packet) SourceIP() netip.Addr {
	addr, _ := netip.AddrFromSlice(b[v6SrcAddr:][:IPv6AddressSize])
	return addr
}

func (b IPv6Packet) DestinationIP() netip.Addr {
	addr, _ := netip.AddrFromSlice(b[v6DstAddr:][:IPv6AddressSize])
	return addr
}

func (IPv6Packet) Checksum() uint16 {
	return 0
}

func (b IPv6Packet) TOS() (uint8, uint32) {
	v := binary.BigEndian.Uint32(b[versTCFL:])
	return uint8(v >> 20), v & 0xfffff
}

func (b IPv6Packet) SetTOS(t uint8, l uint32) {
	vtf := (6 << 28) | (uint32(t) << 20) | (l & 0xfffff)
	binary.BigEndian.PutUint32(b[versTCFL:], vtf)
}

func (b IPv6Packet) SetPayloadLength(payloadLength uint16) {
	binary.BigEndian.PutUint16(b[IPv6PayloadLenOffset:], payloadLength)
}

func (b IPv6Packet) SetSourceIP(addr netip.Addr) {
	if addr.Is6() {
		copy(b[v6SrcAddr:][:IPv6AddressSize], addr.AsSlice())
	}
}

func (b IPv6Packet) SetDestinationIP(addr netip.Addr) {
	if addr.Is6() {
		copy(b[v6DstAddr:][:IPv6AddressSize], addr.AsSlice())
	}
}

func (b IPv6Packet) SetHopLimit(v uint8) {
	b[hopLimit] = v
}

func (b IPv6Packet) SetNextHeader(v byte) {
	b[IPv6NextHeaderOffset] = v
}

func (b IPv6Packet) SetProtocol(p IPProtocol) {
	b.SetNextHeader(p)
}

func (b IPv6Packet) DecTimeToLive() {
	b[hopLimit] = b[hopLimit] - uint8(1)
}

func (IPv6Packet) SetChecksum(uint16) {
}

func (IPv6Packet) ResetChecksum() {
}

func (b IPv6Packet) PseudoSum() uint32 {
	sum := Sum(b[v6SrcAddr:IPv6FixedHeaderSize])
	sum += uint32(b.Protocol())
	sum += uint32(b.PayloadLength())
	return sum
}

func (b IPv6Packet) Valid() bool {
	return len(b) >= IPv6MinimumSize && len(b) >= int(b.PayloadLength())+IPv6MinimumSize
}

func IPVersion(b []byte) int {
	if len(b) < versIHL+1 {
		return -1
	}
	return int(b[versIHL] >> ipVersionShift)
}

var _ IP = (*IPv6Packet)(nil)
