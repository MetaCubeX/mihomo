package windivert

import (
	"encoding/binary"
	"net/netip"
)

type flow struct {
	source      netip.AddrPort
	destination netip.AddrPort
	protocol    byte
}

type packetInfo struct {
	flow
	tcpFlags byte
	offset   int
	size     int
}

// Non-TCP/UDP packets and fragments are left to the Windows network stack.
func parsePacket(p []byte) (info packetInfo, ok bool) {
	if len(p) < 20 {
		return
	}
	var src, dst netip.Addr
	var offset, size int
	switch p[0] >> 4 {
	case 4:
		offset = int(p[0]&15) * 4
		size = int(binary.BigEndian.Uint16(p[2:]))
		if offset < 20 || size < offset || size > len(p) || binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
			return
		}
		src = netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]})
		dst = netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
		info.protocol = p[9]
	case 6:
		if len(p) < 40 {
			return
		}
		offset, size = 40, 40+int(binary.BigEndian.Uint16(p[4:]))
		if size > len(p) {
			return
		}
		src, _ = netip.AddrFromSlice(p[8:24])
		dst, _ = netip.AddrFromSlice(p[24:40])
		info.protocol = p[6]
		for info.protocol == 0 || info.protocol == 43 || info.protocol == 60 {
			if offset+2 > size {
				return info, false
			}
			next := p[offset]
			offset += (int(p[offset+1]) + 1) * 8
			info.protocol = next
		}
	default:
		return
	}
	switch info.protocol {
	case 6:
		if offset+20 > size {
			return info, false
		}
		info.tcpFlags = p[offset+13]
	case 17:
		if offset+8 > size {
			return info, false
		}
	default:
		return info, false
	}
	info.source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(p[offset:]))
	info.destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(p[offset+2:]))
	info.offset, info.size = offset, size
	return info, true
}

func rewriteTCP(p []byte, info packetInfo, source, destination netip.AddrPort) {
	if source.Addr().Is4() {
		copy(p[12:16], source.Addr().AsSlice())
		copy(p[16:20], destination.Addr().AsSlice())
	} else {
		copy(p[8:24], source.Addr().AsSlice())
		copy(p[24:40], destination.Addr().AsSlice())
	}
	binary.BigEndian.PutUint16(p[info.offset:], source.Port())
	binary.BigEndian.PutUint16(p[info.offset+2:], destination.Port())
}
