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
			if !ok || info.source != netip.AddrPortFrom(src, 50000) || info.destination != netip.AddrPortFrom(dst, 443) || info.protocol != protocol || packetDestination(p) != dst {
				t.Fatalf("IPv6=%v TCP=%v: %#v, %v", ipv6, tcp, info, ok)
			}
			batch := append(append([]byte(nil), p...), p...)
			if n := packetSize(batch); n != len(p) || packetSize(batch[n:]) != len(p) {
				t.Fatal("lost packet boundary in batch")
			}
			for _, i := range []int{0, len(p) - 1} {
				if _, ok := parsePacket(p[:i]); ok {
					t.Fatalf("accepted truncated packet at %d", i)
				}
				if packetSize(p[:i]) != 0 {
					t.Fatal("accepted truncated batch packet")
				}
			}
			if !ipv6 {
				p[6] |= 0x20
				if _, ok := parsePacket(p); ok {
					t.Fatal("accepted a fragment")
				}
				if packetSize(p) != len(p) {
					t.Fatal("lost fragment boundary")
				}
			}
		}
	}
}

func FuzzParsePacket(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1})
	for _, ipSize := range []int{20, 40} {
		for _, protocol := range []byte{6, 17} {
			p := make([]byte, ipSize+20)
			if ipSize == 20 {
				p[0], p[9] = 0x45, protocol
				binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
			} else {
				p[0], p[6] = 0x60, protocol
				binary.BigEndian.PutUint16(p[4:], 20)
			}
			if protocol == 6 {
				p[ipSize+12] = 0x50
			} else {
				binary.BigEndian.PutUint16(p[ipSize+4:], 20)
			}
			f.Add(p)
		}
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		size := packetSize(p)
		if size < 0 || size > len(p) {
			t.Fatal("invalid packet size")
		}
		if info, ok := parsePacket(p); ok {
			if info.size > len(p) || info.offset < 20 || info.offset >= info.size {
				t.Fatal("invalid packet bounds")
			}
			if info.protocol != 6 && info.protocol != 17 {
				t.Fatal("unexpected transport")
			}
			if packetDestination(p) != info.destination.Addr() {
				t.Fatal("incorrect packet destination")
			}
		}
	})
}

func TestInvalidTransportHeaders(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		p := make([]byte, 40)
		p[0], p[9] = 0x45, protocol
		binary.BigEndian.PutUint16(p[2:], 40)
		if _, ok := parsePacket(p); ok {
			t.Fatal("zero transport length accepted")
		}
		if protocol == 6 {
			p[32] = 0xf0
		} else {
			binary.BigEndian.PutUint16(p[24:], 100)
		}
		if _, ok := parsePacket(p); ok {
			t.Fatal("truncated transport header accepted")
		}
	}
}
