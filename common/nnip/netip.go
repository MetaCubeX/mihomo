package nnip

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Private IP CIDRs
var privateIPCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/3",
	"::/127",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// IpToAddr converts the net.IP to netip.Addr.
// If slice's length is not 4 or 16, IpToAddr returns netip.Addr{}
func IpToAddr(slice net.IP) netip.Addr {
	ip := slice
	if len(ip) != 4 {
		if ip = slice.To4(); ip == nil {
			ip = slice
		}
	}

	if addr, ok := netip.AddrFromSlice(ip); ok {
		return addr
	}
	return netip.Addr{}
}

// UnMasked returns p's last IP address.
// If p is invalid, UnMasked returns netip.Addr{}
func UnMasked(p netip.Prefix) netip.Addr {
	if !p.IsValid() {
		return netip.Addr{}
	}

	buf := p.Addr().As16()

	hi := binary.BigEndian.Uint64(buf[:8])
	lo := binary.BigEndian.Uint64(buf[8:])

	bits := p.Bits()
	if bits <= 32 {
		bits += 96
	}

	hi = hi | ^uint64(0)>>bits
	lo = lo | ^(^uint64(0) << (128 - bits))

	binary.BigEndian.PutUint64(buf[:8], hi)
	binary.BigEndian.PutUint64(buf[8:], lo)

	addr := netip.AddrFrom16(buf)
	if p.Addr().Is4() {
		return addr.Unmap()
	}
	return addr
}

// IsPrivateIP returns whether IP is private
// If IP is private, return true, else return false
func IsPrivateIP(ip netip.Addr) bool {
	for _, network := range privateIPCIDRs {
		_, subnet, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}
		if subnet.Contains(ip.AsSlice()) {
			return true
		}
	}
	return false
}
