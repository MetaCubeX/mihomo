package loopback

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/iface"
	C "github.com/metacubex/mihomo/constant"
)

func TestCheckPacketConnPort(t *testing.T) {
	const port = 52123
	cases := []struct {
		name string
		ip   netip.Addr
		want bool
	}{
		{"IPv4 loopback", netip.MustParseAddr("127.0.0.1"), true},
		{"IPv4 mapped loopback", netip.MustParseAddr("::ffff:127.0.0.1"), true},
		{"IPv6 loopback", netip.IPv6Loopback(), true},
		{"remote", netip.MustParseAddr("192.0.2.1"), false},
		{"invalid source", netip.Addr{}, false},
	}
	interfaces, err := iface.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, inter := range interfaces {
		for _, prefix := range inter.Addresses {
			local, err := iface.IsLocalIp(prefix.Addr())
			if err != nil {
				t.Fatal(err)
			}
			if local && !prefix.Addr().IsLoopback() {
				cases = append(cases, struct {
					name string
					ip   netip.Addr
					want bool
				}{"interface " + inter.Name + " " + prefix.Addr().String(), prefix.Addr(), true})
			}
		}
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			d := &Detector{}
			metadata := &C.Metadata{SrcIP: test.ip, SrcPort: port}
			err := d.CheckPacketConnPort(metadata, port)
			if errors.Is(err, ErrReject) != test.want || (!test.want && err != nil) {
				t.Fatalf("same port check = %v, reject = %v", err, test.want)
			}
			if err := d.CheckPacketConnPort(metadata, port+1); err != nil {
				t.Fatalf("different port rejected: %v", err)
			}
			var disabled *Detector
			if err := disabled.CheckPacketConnPort(metadata, port); err != nil {
				t.Fatalf("disabled detector rejected: %v", err)
			}
			d.packetConnMap.Store(port, struct{}{})
			if err := d.CheckPacketConn(metadata); errors.Is(err, ErrReject) != test.want || (!test.want && err != nil) {
				t.Fatalf("registered port check = %v, reject = %v", err, test.want)
			}
		})
	}
}
