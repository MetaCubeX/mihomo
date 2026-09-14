//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/hex"
	"testing"

	"github.com/metacubex/mipstack"
)

func TestMIPSChecksums(t *testing.T) {
	for _, test := range []struct{ name, packet string }{
		{"tcp4", "4600002c0000400080060000c0000201c633640101010000c35001bb00000001000000005002ffff00000000"},
		{"udp4", "4500001d0000000040110000c0000201c6336401c35001bb0009000001"},
		{"tcp6", "60000000001c004020010db800000000000000000000000120010db80000000000000000000000020600000000000000c35001bb00000001000000005002ffff00000000"},
		{"udp6", "600000000009114020010db800000000000000000000000120010db8000000000000000000000002c35001bb0009000001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, _ := hex.DecodeString(test.packet)
			info, ok := parsePacket(p)
			// WinDivert can mark a zero IPv4 checksum valid before Windows fills it in.
			if !ok || !completeChecksums(p, info, flagIPChecksum) {
				t.Fatal("could not complete outbound checksums")
			}
			parsed, err := mipstack.ParseIPPacket(p)
			if err == nil {
				if info.protocol == 6 {
					_, err = parsed.TCPSegment()
				} else {
					_, err = parsed.UDPDatagram()
				}
			}
			if err != nil {
				t.Fatalf("MIPS rejected the completed packet: %v", err)
			}
		})
	}
}
