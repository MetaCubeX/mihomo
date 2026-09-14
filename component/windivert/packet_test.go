package windivert

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParsePacket(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			headerSize, transportSize := 20, 8
			if ipv6 {
				headerSize = 48 // includes a hop-by-hop header
			}
			if tcp {
				transportSize = 20
			}
			p := make([]byte, headerSize+transportSize)
			protocol := byte(17)
			if tcp {
				protocol = 6
				p[headerSize+12] = 0x50
				p[headerSize+13] = 2
			} else {
				binary.BigEndian.PutUint16(p[headerSize+4:], uint16(transportSize))
			}
			var src, dst netip.Addr
			if ipv6 {
				p[0], p[6], p[40] = 0x60, 0, protocol
				binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
				src, dst = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
				copy(p[8:24], src.AsSlice())
				copy(p[24:40], dst.AsSlice())
			} else {
				p[0], p[9] = 0x45, protocol
				binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
				src, dst = netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
				copy(p[12:16], src.AsSlice())
				copy(p[16:20], dst.AsSlice())
			}
			binary.BigEndian.PutUint16(p[headerSize:], 50000)
			binary.BigEndian.PutUint16(p[headerSize+2:], 443)
			info, ok := parsePacket(p)
			if !ok || info.source != netip.AddrPortFrom(src, 50000) || info.destination != netip.AddrPortFrom(dst, 443) || info.protocol != protocol {
				t.Fatalf("IPv6=%v TCP=%v: %#v, %v", ipv6, tcp, info, ok)
			}
			for _, i := range []int{0, len(p) - 1} {
				if _, ok := parsePacket(p[:i]); ok {
					t.Fatalf("accepted truncated packet at %d", i)
				}
			}
			if !ipv6 {
				p[6] |= 0x20
				if _, ok := parsePacket(p); ok {
					t.Fatal("accepted a fragment")
				}
			}
		}
	}
}
