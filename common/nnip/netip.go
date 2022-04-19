package nnip

import (
	"encoding/binary"
	"net"
	"net/netip"
)

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
