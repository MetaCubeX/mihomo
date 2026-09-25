//go:build windows && (amd64 || 386)

package windivert

import (
	"net/netip"
	"testing"

	"github.com/metacubex/sing/common/ranges"
	"golang.org/x/exp/slices"
)

// Interpret the public WinDivert 2.2 instruction ABI independently of the
// expression builder, including a false result for fields of another protocol.
func evaluateFilter(t *testing.T, code []instruction, info packetInfo, addr address) bool {
	t.Helper()
	for pc, steps := uint16(0), 0; steps <= len(code); steps++ {
		if pc == accept {
			return true
		}
		if pc == reject {
			return false
		}
		if int(pc) >= len(code) {
			t.Fatalf("invalid filter jump %d", pc)
		}
		ins := code[pc]
		field, test := ins.FieldTestSuccess&0x7ff, (ins.FieldTestSuccess>>11)&31
		var value [4]uint32
		valid := true
		bit := func(v bool) uint32 {
			if v {
				return 1
			}
			return 0
		}
		ipv4, tcp := info.source.Addr().Is4(), info.protocol == 6
		switch field {
		case 0:
		case 2:
			value[0] = bit(addr.Flags&flagOutbound != 0)
		case 3:
			value[0] = addr.IfIdx
		case 5:
			value[0] = bit(ipv4)
		case 6:
			value[0] = bit(!ipv4)
		case 8:
			value[0] = bit(tcp)
		case 9:
			value[0] = bit(info.protocol == 17)
		case 58:
			value[0] = bit(addr.Flags&flagLoopback != 0)
		case 59:
			value[0] = bit(addr.Flags&(1<<19) != 0)
		case 85:
		case 21, 22, 28, 29:
			valid = (field < 28) == ipv4
			ip := info.destination.Addr()
			if field == 21 || field == 28 {
				ip = info.source.Addr()
			}
			b := ip.As16()
			for i := range b {
				value[3-i/4] |= uint32(b[i]) << uint(24-8*(i%4))
			}
		case 38, 39, 53, 54:
			valid = (field < 53) == tcp
			value[0] = uint32(info.destination.Port())
			if field == 38 || field == 53 {
				value[0] = uint32(info.source.Port())
			}
		default:
			t.Fatalf("unexpected field %d", field)
		}
		cmp := 0
		for i := 3; i >= 0; i-- {
			if value[i] < ins.Arg[i] {
				cmp = -1
				break
			}
			if value[i] > ins.Arg[i] {
				cmp = 1
				break
			}
		}
		matched := false
		switch test {
		case 0:
			matched = cmp == 0
		case 1:
			matched = cmp != 0
		case 2:
			matched = cmp < 0
		case 3:
			matched = cmp <= 0
		case 4:
			matched = cmp > 0
		case 5:
			matched = cmp >= 0
		default:
			t.Fatalf("invalid test %d", test)
		}
		next := uint16(ins.Failure)
		if valid && matched {
			next = uint16(ins.FieldTestSuccess >> 16)
		}
		if next < accept && next <= pc {
			t.Fatal("non-forward filter jump")
		}
		pc = next
	}
	t.Fatal("filter did not terminate")
	return false
}

func TestKernelFilterPolicy(t *testing.T) {
	device := &Tun{options: Options{IPv6: true,
		RouteAddress:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		ExcludeAddress: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/48")},
		ExcludeSrcPort: []uint16{1234}, ExcludeDstPort: []uint16{53},
		ExcludeSrcPortRange: []ranges.Range[uint16]{{Start: 100, End: 200}}, ExcludeDstPortRange: []ranges.Range[uint16]{{Start: 8000, End: 9000}},
	}, includeIf: map[uint32]bool{1: true, 2: true}, excludeIf: map[uint32]bool{2: true}}
	code, err := device.networkFilter()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		destination      string
		srcPort, dstPort uint16
		ifIdx            uint32
		want             bool
	}{
		{"203.0.113.1", 99, 7999, 1, true},
		{"203.0.113.1", 100, 443, 1, false},
		{"203.0.113.1", 200, 443, 1, false},
		{"203.0.113.1", 201, 9001, 1, true},
		{"203.0.113.1", 1234, 443, 1, false},
		{"203.0.113.1", 50000, 53, 1, false},
		{"203.0.113.1", 50000, 8000, 1, false},
		{"203.0.113.1", 50000, 9000, 1, false},
		{"203.0.113.1", 50000, 443, 2, false},
		{"203.0.113.1", 50000, 443, 3, false},
		{"192.0.2.255", 50000, 443, 1, false},
		{"192.0.3.0", 50000, 443, 1, true},
		{"2001:db8:1::1", 50000, 443, 1, false},
		{"2001:db8:2::1", 50000, 443, 1, true},
		{"0.0.0.0", 50000, 443, 1, false},
		{"127.0.0.1", 50000, 443, 1, false},
		{"169.254.1.1", 50000, 443, 1, false},
		{"224.0.0.1", 50000, 443, 1, false},
		{"255.255.255.255", 50000, 443, 1, false},
		{"::", 50000, 443, 1, false},
		{"::1", 50000, 443, 1, false},
		{"fe80::1", 50000, 443, 1, false},
		{"ff02::1", 50000, 443, 1, false},
	} {
		for _, protocol := range []byte{6, 17} {
			dst := netip.MustParseAddr(test.destination)
			src := netip.MustParseAddr("198.51.100.1")
			if dst.Is6() {
				src = netip.MustParseAddr("2001:db8::2")
			}
			info := packetInfo{flow: flow{source: netip.AddrPortFrom(src, test.srcPort), destination: netip.AddrPortFrom(dst, test.dstPort), protocol: protocol}}
			addr := address{Flags: flagOutbound, IfIdx: test.ifIdx}
			if got := evaluateFilter(t, code, info, addr); got != test.want {
				t.Fatalf("flow=%+v interface=%d: got %v, want %v", info, test.ifIdx, got, test.want)
			}
		}
	}
}

func TestKernelDNSWithoutIPv6Traffic(t *testing.T) {
	for _, test := range []struct {
		target   string
		captured []string
	}{
		{"0.0.0.0:53", []string{"[2001:db8::53]:53"}},
		{"[::]:5353", []string{"[2001:db8::53]:53"}},
		{"[2001:db8::53]:5353", []string{"[2001:db8::53]:5353"}},
		{"192.0.2.53:53", nil},
	} {
		device := &Tun{options: Options{HijackDNS: []netip.AddrPort{netip.MustParseAddrPort(test.target)}}}
		code, err := device.networkFilter()
		if err != nil {
			t.Fatal(err)
		}
		for _, destination := range []string{"192.0.2.53:443", "[2001:db8::53]:53", "[2001:db8::53]:5353", "[2001:db8::54]:5353", "[2001:db8::53]:443"} {
			for _, protocol := range []byte{6, 17} {
				info := packetInfo{flow: flow{destination: netip.MustParseAddrPort(destination), protocol: protocol}}
				info.source = netip.MustParseAddrPort("[2001:db8::1]:12345")
				if info.destination.Addr().Is4() {
					info.source = netip.MustParseAddrPort("192.0.2.1:12345")
				}
				addr := address{Flags: flagOutbound}
				want := info.destination.Addr().Is4() || slices.Contains(test.captured, destination)
				if got := evaluateFilter(t, code, info, addr); got != want {
					t.Fatalf("DNS target=%s destination=%s protocol=%d: got %v, want %v", test.target, destination, protocol, got, want)
				}
			}
		}
	}
}

func TestKernelDNSRoutePolicy(t *testing.T) {
	for _, policy := range []struct {
		name             string
		routes, excludes []netip.Prefix
	}{
		{"excluded-address", nil, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}},
		{"outside-route", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}, nil},
	} {
		t.Run(policy.name, func(t *testing.T) {
			device := &Tun{options: Options{
				IPv6:           true,
				HijackDNS:      []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:53"), netip.MustParseAddrPort("192.168.160.1:5353")},
				RouteAddress:   policy.routes,
				ExcludeAddress: policy.excludes,
				ExcludeSrcPort: []uint16{1234},
			}, includeIf: map[uint32]bool{1: true, 2: true}, excludeIf: map[uint32]bool{2: true}}
			code, err := device.networkFilter()
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				destination string
				srcPort     uint16
				ifIdx       uint32
				want        bool
			}{
				{"192.168.160.1:53", 50000, 1, true},
				{"[fd00::53]:53", 50000, 1, true},
				{"192.168.160.1:5353", 50000, 1, true},
				{"192.168.160.2:5353", 50000, 1, false},
				{"192.168.160.1:443", 50000, 1, false},
				{"[fd00::53]:443", 50000, 1, false},
				{"203.0.113.1:443", 50000, 1, true},
				{"192.168.160.1:53", 1234, 1, false},
				{"192.168.160.1:53", 50000, 2, false},
				{"192.168.160.1:53", 50000, 3, false},
			} {
				for _, protocol := range []byte{6, 17} {
					dst := netip.MustParseAddrPort(test.destination)
					src := netip.MustParseAddr("198.51.100.1")
					if dst.Addr().Is6() {
						src = netip.MustParseAddr("2001:db8::1")
					}
					info := packetInfo{flow: flow{source: netip.AddrPortFrom(src, test.srcPort), destination: dst, protocol: protocol}}
					if got := evaluateFilter(t, code, info, address{Flags: flagOutbound, IfIdx: test.ifIdx}); got != test.want {
						t.Errorf("flow=%+v interface=%d: got %v, want %v", info, test.ifIdx, got, test.want)
					}
				}
			}
		})
	}
}

func TestKernelFilterRelayScope(t *testing.T) {
	device := &Tun{tcp: &tcpRedirect{ports: [2]uint16{50001, 50002}}, options: Options{RouteAddress: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}}}
	code, err := device.networkFilter()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		info := packetInfo{flow: flow{source: netip.AddrPortFrom(ip, device.tcp.port(ip)), destination: netip.AddrPortFrom(relayPeer(ip), 10000), protocol: 6}}
		addr := address{Flags: flagOutbound | flagLoopback}
		if !evaluateFilter(t, code, info, addr) {
			t.Fatal("relay reply bypassed route exclusions")
		}
		info.source = netip.AddrPortFrom(ip, 50003)
		if evaluateFilter(t, code, info, addr) {
			t.Fatal("unrelated loopback service intercepted")
		}
	}
	device.options.RouteAddress = make([]netip.Prefix, 256)
	for i := range device.options.RouteAddress {
		device.options.RouteAddress[i] = netip.MustParsePrefix("203.0.113.1/32")
	}
	if _, err := device.networkFilter(); err == nil {
		t.Fatal("oversized filter accepted")
	}
}
