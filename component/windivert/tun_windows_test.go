//go:build windows && (amd64 || 386)

package windivert

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestDNSWithoutIPv6Traffic(t *testing.T) {
	device := &Tun{options: Options{HijackDNS: func(destination netip.AddrPort) bool { return destination.Port() == 53 }}}
	info := packetInfo{flow: flow{destination: netip.MustParseAddrPort("[fd00::1]:53")}}
	if !device.selected(info, address{}) {
		t.Fatal("IPv6 DNS was bypassed")
	}
	info.destination = netip.MustParseAddrPort("[fd00::1]:443")
	if device.selected(info, address{}) {
		t.Fatal("IPv6 traffic was captured while disabled")
	}
}

func TestTCPCapture(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	info := packetInfo{flow: flow{source: conn.LocalAddr().(*net.TCPAddr).AddrPort(),
		destination: conn.RemoteAddr().(*net.TCPAddr).AddrPort(), protocol: 6}, tcpFlags: 0x10}
	device := &Tun{pid: uint32(os.Getpid()), tcpFlows: make(map[flow]uint32)}
	if device.capture(info) {
		t.Fatal("captured a connection established before startup")
	}
	info.tcpFlags = 0x02
	if device.capture(info) {
		t.Fatal("captured the listener's own connection")
	}
	device.pid = 0 // Treat the test socket as a different process.
	stale := flow{source: netip.MustParseAddrPort("127.0.0.1:0"), protocol: 6}
	device.tcpFlows[stale] = uint32(os.Getpid())
	if !device.capture(info) {
		t.Fatal("did not capture a new connection")
	}
	if _, found := device.tcpFlows[stale]; found {
		t.Fatal("retained a socket absent from the current TCP table")
	}
	info.tcpFlags = 0x10
	if !device.capture(info) {
		t.Fatal("lost an active captured connection")
	}
	info.tcpFlags = 0x04
	if !device.capture(info) || device.capture(info) {
		t.Fatal("reset must be captured once and remove the flow")
	}
}
