package iface

import (
	"net"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsInterfaceFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind uint32
		want net.Flags
	}{
		{"ethernet", 6, net.FlagBroadcast | net.FlagMulticast},
		{"token-ring", 9, net.FlagBroadcast | net.FlagMulticast},
		{"fddi-not-classified-by-net", 15, 0},
		{"lapb-not-classified-by-net", 16, 0},
		{"wifi", 71, net.FlagBroadcast | net.FlagMulticast},
		{"firewire", 144, net.FlagBroadcast | net.FlagMulticast},
		{"ppp", 23, net.FlagPointToPoint | net.FlagMulticast},
		{"tunnel", 131, net.FlagPointToPoint | net.FlagMulticast},
		{"loopback", 24, net.FlagLoopback | net.FlagMulticast},
		{"atm", 37, net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast},
		{"other", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := windows.IpAdapterAddresses{IfType: tc.kind, OperStatus: windows.IfOperStatusDown}
			if got := snapshotFromAdapter(&adapter).Flags; got != tc.want {
				t.Fatalf("down flags: got %v, want %v", got, tc.want)
			}
			adapter.OperStatus = windows.IfOperStatusUp
			if got := snapshotFromAdapter(&adapter).Flags; got != tc.want|net.FlagUp|net.FlagRunning {
				t.Fatalf("up flags: got %v", got)
			}
		})
	}
}

func TestWindowsSnapshotOwnsAddressesAndPreservesMetadata(t *testing.T) {
	name, err := windows.UTF16FromString("virtual-test")
	if err != nil {
		t.Fatal(err)
	}
	ipv4 := syscall.RawSockaddrInet4{Family: syscall.AF_INET, Addr: [4]byte{192, 0, 2, 9}}
	ipv6 := syscall.RawSockaddrInet6{Family: syscall.AF_INET6, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}}
	anycast := syscall.RawSockaddrInet4{Family: syscall.AF_INET, Addr: [4]byte{192, 0, 2, 10}}
	v6 := windows.IpAdapterUnicastAddress{Address: windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(&ipv6)), SockaddrLength: int32(unsafe.Sizeof(ipv6))}, OnLinkPrefixLength: 64}
	v4 := windows.IpAdapterUnicastAddress{Address: windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(&ipv4)), SockaddrLength: int32(unsafe.Sizeof(ipv4))}, OnLinkPrefixLength: 24, Next: &v6}
	other := windows.IpAdapterAnycastAddress{Address: windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(&anycast)), SockaddrLength: int32(unsafe.Sizeof(anycast))}}
	adapter := windows.IpAdapterAddresses{Ipv6IfIndex: 42, Mtu: ^uint32(0), FriendlyName: &name[0], FirstUnicastAddress: &v4, FirstAnycastAddress: &other, PhysicalAddressLength: 6, PhysicalAddress: [8]byte{0, 1, 2, 3, 4, 5}}
	got := snapshotFromAdapter(&adapter)
	if got.Index != 42 || got.MTU != -1 || got.Name != "virtual-test" || got.HardwareAddr.String() != "00:01:02:03:04:05" {
		t.Fatalf("unexpected metadata: %+v", got.Interface)
	}
	want := []string{"192.0.2.9/24", "2001:db8::9/64", "192.0.2.10"}
	if len(got.Addrs) != len(want) {
		t.Fatalf("address count %d, want %d", len(got.Addrs), len(want))
	}
	// Mutating the API buffer after decoding must not alter cached values.
	ipv4.Addr[3], ipv6.Addr[15], anycast.Addr[3] = 99, 99, 99
	adapter.PhysicalAddress[0] = 99
	name[0] = 'X'
	for i, address := range got.Addrs {
		if address.String() != want[i] {
			t.Errorf("address %d: got %s, want %s", i, address, want[i])
		}
	}
	if got.Name != "virtual-test" || got.HardwareAddr.String() != "00:01:02:03:04:05" {
		t.Fatal("metadata aliases the input buffer")
	}
}
