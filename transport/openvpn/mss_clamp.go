package openvpn

import "encoding/binary"

const (
	ipVersion4    = 4
	ipVersion6    = 6
	ipv4MinHeader = 20
	ipv6Header    = 40
	ipProtoTCP    = 6
	tcpMinHeader  = 20
	tcpFlagSYN    = 0x02
)

func clampTCPSegmentMSS(packet []byte, maximum uint16) []byte {
	if maximum == 0 || len(packet) == 0 {
		return packet
	}
	effective := maximum
	if packet[0]>>4 == ipVersion6 {
		if effective <= ipv6Header-ipv4MinHeader {
			return packet
		}
		effective -= ipv6Header - ipv4MinHeader
	}
	tcpOffset, valueOffset, advertised, ok := locateTCPMSS(packet)
	if !ok || advertised <= effective {
		return packet
	}
	out := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(out[valueOffset:valueOffset+2], effective)
	checksumOffset := tcpOffset + 16
	oldChecksum := binary.BigEndian.Uint16(out[checksumOffset : checksumOffset+2])
	binary.BigEndian.PutUint16(out[checksumOffset:checksumOffset+2], updateChecksum16(oldChecksum, advertised, effective))
	return out
}

func locateTCPMSS(packet []byte) (tcpOffset, valueOffset int, value uint16, ok bool) {
	if len(packet) == 0 {
		return
	}
	var ipLen int
	switch packet[0] >> 4 {
	case ipVersion4:
		if len(packet) < ipv4MinHeader || packet[9] != ipProtoTCP {
			return
		}
		ipLen = int(packet[0]&0x0f) * 4
		if ipLen < ipv4MinHeader || ipLen > len(packet) {
			return 0, 0, 0, false
		}
	case ipVersion6:
		if len(packet) < ipv6Header || packet[6] != ipProtoTCP {
			return
		}
		ipLen = ipv6Header
	default:
		return
	}
	tcp := packet[ipLen:]
	if len(tcp) < tcpMinHeader || tcp[13]&tcpFlagSYN == 0 {
		return 0, 0, 0, false
	}
	tcpLen := int(tcp[12]>>4) * 4
	if tcpLen < tcpMinHeader || tcpLen > len(tcp) {
		return 0, 0, 0, false
	}
	for off := tcpMinHeader; off < tcpLen; {
		kind := tcp[off]
		if kind == 0 {
			return 0, 0, 0, false
		}
		if kind == 1 {
			off++
			continue
		}
		if off+1 >= tcpLen {
			return 0, 0, 0, false
		}
		length := int(tcp[off+1])
		if length < 2 || off+length > tcpLen {
			return 0, 0, 0, false
		}
		if kind == 2 && length == 4 {
			return ipLen, ipLen + off + 2, binary.BigEndian.Uint16(tcp[off+2 : off+4]), true
		}
		off += length
	}
	return 0, 0, 0, false
}

func updateChecksum16(checksum, oldWord, newWord uint16) uint16 {
	sum := uint32(^checksum) + uint32(^oldWord) + uint32(newWord)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
