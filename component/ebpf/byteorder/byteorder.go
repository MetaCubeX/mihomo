package byteorder

import (
	"net"
)

// NetIPv4ToHost32 converts an net.IP to a uint32 in host byte order. ip
// must be a IPv4 address, otherwise the function will panic.
func NetIPv4ToHost32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	_ = ipv4[3] // Assert length of ipv4.
	return Native.Uint32(ipv4)
}
