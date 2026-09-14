//go:build windows && (amd64 || 386)

package windivert

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	tun "github.com/metacubex/sing-tun"
)

func TestTCPRedirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &tcpRedirect{nat: tun.NewNat(ctx, time.Minute), ports: [2]uint16{18474, 18475}}
	for _, ipv6 := range []bool{false, true} {
		source := netip.MustParseAddrPort("192.0.2.1:50000")
		destination := netip.MustParseAddrPort("198.51.100.1:443")
		headerLen := 20
		if ipv6 {
			source = netip.MustParseAddrPort("[2001:db8::1]:50000")
			destination = netip.MustParseAddrPort("[2001:db8::2]:443")
			headerLen = 48 // Include an IPv6 extension header.
		}
		p := make([]byte, headerLen+20)
		if ipv6 {
			p[0], p[6], p[40] = 0x60, 0, 6
			binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		} else {
			p[0], p[9] = 0x45, 6
			binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		}
		p[headerLen+12], p[headerLen+13] = 0x50, 2
		info := packetInfo{flow: flow{source: source, destination: destination, protocol: 6}, offset: headerLen}
		r.redirect(p, info)
		redirected, ok := parsePacket(p)
		if !ok || redirected.destination != netip.AddrPortFrom(source.Addr(), r.port(source.Addr())) ||
			redirected.source.Addr() != destination.Addr() {
			t.Fatalf("incorrect redirect: %+v", redirected)
		}
		reply := packetInfo{flow: flow{source: redirected.destination, destination: redirected.source, protocol: 6}, offset: headerLen}
		rewriteTCP(p, reply, reply.source, reply.destination)
		device := &Tun{tcp: r}
		addr, inject := device.processPacket(p, address{Flags: ^uint32(0), IfIdx: 3, SubIfIdx: 4})
		if !inject || addr != (address{IfIdx: 3, SubIfIdx: 4}) {
			t.Fatalf("incorrect reply injection: address=%+v inject=%v", addr, inject)
		}
		restored, ok := parsePacket(p)
		if !ok || restored.source != destination || restored.destination != source {
			t.Fatalf("original endpoints lost: %+v", restored)
		}
	}
}
