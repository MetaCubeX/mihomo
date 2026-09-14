//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"unsafe"
)

func TestAddressLayout(t *testing.T) {
	if unsafe.Sizeof(address{}) != 80 || unsafe.Offsetof(address{}.IfIdx) != 16 {
		t.Fatal("WinDivert ABI layout mismatch")
	}
}

func TestSocketOwner(t *testing.T) {
	device := new(Tun)
	for _, network := range []string{"udp4", "udp6"} {
		conn, err := net.ListenPacket(network, ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
		ip := netip.MustParseAddr("127.0.0.1")
		if network == "udp6" {
			ip = netip.IPv6Loopback()
		}
		key := flow{source: netip.AddrPortFrom(ip, addr.Port()), protocol: 17}
		owners, err := device.socketTable(key)
		if err != nil || owners[key] != uint32(os.Getpid()) {
			t.Fatalf("%s owner=%d err=%v", network, owners[key], err)
		}
	}
}

func TestSharedUDPSocket(t *testing.T) {
	for _, source := range []string{"192.0.2.1:50000", "[2001:db8::1]:50000"} {
		key := flow{source: netip.MustParseAddrPort(source), protocol: 17}
		rowSize, portOffset, pidOffset := 12, 4, 8
		if key.source.Addr().Is6() {
			rowSize, portOffset, pidOffset = 28, 20, 24
		}
		// A wildcard socket and an address-specific socket share one port.
		data := make([]byte, 4+2*rowSize)
		binary.LittleEndian.PutUint32(data, 2)
		wildcard, exact := data[4:4+rowSize], data[4+rowSize:]
		copy(exact, key.source.Addr().AsSlice())
		for _, row := range [][]byte{wildcard, exact} {
			binary.BigEndian.PutUint16(row[portOffset:], key.source.Port())
			binary.LittleEndian.PutUint32(row[pidOffset:], 7)
		}
		for _, owner := range []uint32{7, 8} {
			binary.LittleEndian.PutUint32(exact[pidOffset:], owner)
			owners := parseSocketTable(data, key)
			want := uint32(7)
			if owner != 7 {
				want = 0
			}
			if owners[key] != want {
				t.Fatalf("%s owner=%d: got %d, want %d", source, owner, owners[key], want)
			}
		}
	}
}
