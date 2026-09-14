//go:build windows && (amd64 || 386)

package windivert

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/metacubex/mipstack"
)

func mipsTestPacket(t *testing.T, ipv6 bool, protocol byte, data []byte) ([]byte, packetInfo) {
	t.Helper()
	headerLen, transportLen := 24, 8 // Exercise IPv4 options as well as IPv6 extensions.
	source, destination := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	if ipv6 {
		headerLen = 48
		source, destination = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	}
	if protocol == 6 {
		transportLen = 20
	}
	p := make([]byte, headerLen+transportLen+len(data))
	if ipv6 {
		p[0], p[6], p[7], p[40] = 0x60, 0, 64, protocol
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		copy(p[8:24], source.AsSlice())
		copy(p[24:40], destination.AsSlice())
	} else {
		p[0], p[8], p[9], p[10] = 0x46, 64, protocol, 0x12
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		copy(p[12:16], source.AsSlice())
		copy(p[16:20], destination.AsSlice())
	}
	binary.BigEndian.PutUint16(p[headerLen:], 50000)
	binary.BigEndian.PutUint16(p[headerLen+2:], 443)
	if protocol == 6 {
		p[headerLen+12], p[headerLen+13], p[headerLen+16] = 0x50, 0x18, 0x34
	} else {
		binary.BigEndian.PutUint16(p[headerLen+4:], uint16(transportLen+len(data)))
		p[headerLen+6] = 0x34
	}
	copy(p[headerLen+transportLen:], data)
	info, ok := parsePacket(p)
	if !ok {
		t.Fatal("invalid test packet")
	}
	return p, info
}

func TestMIPSChecksums(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, protocol := range []byte{6, 17} {
			t.Run(fmt.Sprintf("ipv6=%v/protocol=%d", ipv6, protocol), func(t *testing.T) {
				p, info := mipsTestPacket(t, ipv6, protocol, []byte("hello"))
				if !completeChecksums(p, info, 0) {
					t.Fatal("could not complete offloaded checksums")
				}
				parsed, err := mipstack.ParseIPPacket(p)
				if err == nil {
					if protocol == 6 {
						_, err = parsed.TCPSegment()
					} else {
						_, err = parsed.UDPDatagram()
					}
				}
				if err != nil {
					t.Fatalf("MIPS rejected the completed packet: %v", err)
				}
				// Corruption in a packet marked checksum-valid must still be rejected by MIPS.
				p[len(p)-1] ^= 1
				before := append([]byte(nil), p...)
				if !completeChecksums(p, info, flagIPChecksum|flagTCPChecksum|flagUDPChecksum) || !bytes.Equal(p, before) {
					t.Fatal("modified a packet whose checksums were not offloaded")
				}
				if protocol == 6 {
					_, err = parsed.TCPSegment()
				} else {
					_, err = parsed.UDPDatagram()
				}
				if err == nil {
					t.Fatal("accepted corrupted transport payload")
				}
			})
		}
	}
}

func TestMIPSUDPChecksumLength(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		p, info := mipsTestPacket(t, ipv6, 17, []byte{0, 0})
		payload := p[info.offset:]
		payload[6], payload[7] = 0, 0
		value, err := mipstack.IPTransportChecksum(info.source.Addr(), info.destination.Addr(), 17, payload)
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(payload[8:], value) // Make the computed checksum zero.
		if !completeChecksums(p, info, 0) || binary.BigEndian.Uint16(payload[6:]) != 0xffff {
			t.Fatal("a computed zero UDP checksum must be encoded as 0xffff")
		}
		for _, length := range []uint16{0, 7, 65535} {
			binary.BigEndian.PutUint16(payload[4:], length)
			for _, flags := range []uint32{0, flagIPChecksum | flagUDPChecksum} {
				if completeChecksums(p, info, flags) {
					t.Fatalf("accepted invalid UDP length %d", length)
				}
			}
		}
	}
}

func TestMIPSZeroIPv4ChecksumMarkedValid(t *testing.T) {
	p, info := mipsTestPacket(t, false, 6, nil)
	p[10], p[11] = 0, 0
	if !completeChecksums(p, info, flagIPChecksum) {
		t.Fatal("could not complete the zero IPv4 checksum")
	}
	parsed, err := mipstack.ParseIPPacket(p)
	if err == nil {
		_, err = parsed.TCPSegment()
	}
	if err != nil {
		t.Fatalf("MIPS rejected the completed packet: %v", err)
	}
}
