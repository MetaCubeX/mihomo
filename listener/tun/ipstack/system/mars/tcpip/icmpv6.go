package tcpip

import (
	"encoding/binary"
)

type ICMPv6Packet []byte

const (
	ICMPv6HeaderSize = 4

	ICMPv6MinimumSize = 8

	ICMPv6PayloadOffset = 8

	ICMPv6EchoMinimumSize = 8

	ICMPv6ErrorHeaderSize = 8

	ICMPv6DstUnreachableMinimumSize = ICMPv6MinimumSize

	ICMPv6PacketTooBigMinimumSize = ICMPv6MinimumSize

	ICMPv6ChecksumOffset = 2

	icmpv6PointerOffset = 4

	icmpv6MTUOffset = 4

	icmpv6IdentOffset = 4

	icmpv6SequenceOffset = 6

	NDPHopLimit = 255
)

type ICMPv6Type byte

const (
	ICMPv6DstUnreachable ICMPv6Type = 1
	ICMPv6PacketTooBig   ICMPv6Type = 2
	ICMPv6TimeExceeded   ICMPv6Type = 3
	ICMPv6ParamProblem   ICMPv6Type = 4
	ICMPv6EchoRequest    ICMPv6Type = 128
	ICMPv6EchoReply      ICMPv6Type = 129

	ICMPv6RouterSolicit   ICMPv6Type = 133
	ICMPv6RouterAdvert    ICMPv6Type = 134
	ICMPv6NeighborSolicit ICMPv6Type = 135
	ICMPv6NeighborAdvert  ICMPv6Type = 136
	ICMPv6RedirectMsg     ICMPv6Type = 137

	ICMPv6MulticastListenerQuery  ICMPv6Type = 130
	ICMPv6MulticastListenerReport ICMPv6Type = 131
	ICMPv6MulticastListenerDone   ICMPv6Type = 132
)

func (typ ICMPv6Type) IsErrorType() bool {
	return typ&0x80 == 0
}

type ICMPv6Code byte

const (
	ICMPv6NetworkUnreachable ICMPv6Code = 0
	ICMPv6Prohibited         ICMPv6Code = 1
	ICMPv6BeyondScope        ICMPv6Code = 2
	ICMPv6AddressUnreachable ICMPv6Code = 3
	ICMPv6PortUnreachable    ICMPv6Code = 4
	ICMPv6Policy             ICMPv6Code = 5
	ICMPv6RejectRoute        ICMPv6Code = 6
)

const (
	ICMPv6HopLimitExceeded  ICMPv6Code = 0
	ICMPv6ReassemblyTimeout ICMPv6Code = 1
)

const (
	ICMPv6ErroneousHeader ICMPv6Code = 0

	ICMPv6UnknownHeader ICMPv6Code = 1

	ICMPv6UnknownOption ICMPv6Code = 2
)

const ICMPv6UnusedCode ICMPv6Code = 0

func (b ICMPv6Packet) Type() ICMPv6Type {
	return ICMPv6Type(b[0])
}

func (b ICMPv6Packet) SetType(t ICMPv6Type) {
	b[0] = byte(t)
}

func (b ICMPv6Packet) Code() ICMPv6Code {
	return ICMPv6Code(b[1])
}

func (b ICMPv6Packet) SetCode(c ICMPv6Code) {
	b[1] = byte(c)
}

func (b ICMPv6Packet) TypeSpecific() uint32 {
	return binary.BigEndian.Uint32(b[icmpv6PointerOffset:])
}

func (b ICMPv6Packet) SetTypeSpecific(val uint32) {
	binary.BigEndian.PutUint32(b[icmpv6PointerOffset:], val)
}

func (b ICMPv6Packet) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[ICMPv6ChecksumOffset:])
}

func (b ICMPv6Packet) SetChecksum(sum [2]byte) {
	_ = b[ICMPv6ChecksumOffset+1]
	b[ICMPv6ChecksumOffset] = sum[0]
	b[ICMPv6ChecksumOffset+1] = sum[1]
}

func (ICMPv6Packet) SourcePort() uint16 {
	return 0
}

func (ICMPv6Packet) DestinationPort() uint16 {
	return 0
}

func (ICMPv6Packet) SetSourcePort(uint16) {
}

func (ICMPv6Packet) SetDestinationPort(uint16) {
}

func (b ICMPv6Packet) MTU() uint32 {
	return binary.BigEndian.Uint32(b[icmpv6MTUOffset:])
}

func (b ICMPv6Packet) SetMTU(mtu uint32) {
	binary.BigEndian.PutUint32(b[icmpv6MTUOffset:], mtu)
}

func (b ICMPv6Packet) Ident() uint16 {
	return binary.BigEndian.Uint16(b[icmpv6IdentOffset:])
}

func (b ICMPv6Packet) SetIdent(ident uint16) {
	binary.BigEndian.PutUint16(b[icmpv6IdentOffset:], ident)
}

func (b ICMPv6Packet) Sequence() uint16 {
	return binary.BigEndian.Uint16(b[icmpv6SequenceOffset:])
}

func (b ICMPv6Packet) SetSequence(sequence uint16) {
	binary.BigEndian.PutUint16(b[icmpv6SequenceOffset:], sequence)
}

func (b ICMPv6Packet) MessageBody() []byte {
	return b[ICMPv6HeaderSize:]
}

func (b ICMPv6Packet) Payload() []byte {
	return b[ICMPv6PayloadOffset:]
}

func (b ICMPv6Packet) ResetChecksum(psum uint32) {
	b.SetChecksum(zeroChecksum)
	b.SetChecksum(Checksum(psum, b))
}
