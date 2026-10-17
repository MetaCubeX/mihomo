package sudoku

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/transport/socks5"
)

// EncodeAddress returns the SOCKS5 encoding of rawAddr ("host:port").
func EncodeAddress(rawAddr string) ([]byte, error) {
	return AppendAddress(nil, rawAddr)
}

// AppendAddress appends the SOCKS5 encoding of rawAddr ("host:port") to dst; dst is returned
// unchanged on error. IPv4-mapped IPv6 literals are encoded as IPv4 and IPv6 zones are dropped.
func AppendAddress(dst []byte, rawAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return dst, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return dst, err
	}

	if i := strings.IndexByte(host, '%'); i >= 0 {
		// Zone identifiers are not representable in SOCKS5 IPv6 address encoding.
		host = host[:i]
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return AppendAddrPort(dst, netip.AddrPortFrom(ip, uint16(port))), nil
	}
	if len(host) > 255 {
		return dst, errors.New("domain too long")
	}
	dst = append(dst, socks5.AtypDomainName, byte(len(host)))
	dst = append(dst, host...)
	return append(dst, byte(port>>8), byte(port)), nil
}

// AppendAddrPort appends the SOCKS5 encoding of an IP destination to dst. IPv4-mapped IPv6
// addresses are encoded as IPv4 and zones are dropped.
func AppendAddrPort(dst []byte, ap netip.AddrPort) []byte {
	if ip := ap.Addr().Unmap(); ip.Is4() {
		v := ip.As4()
		dst = append(dst, socks5.AtypIPv4)
		dst = append(dst, v[:]...)
	} else {
		v := ip.As16()
		dst = append(dst, socks5.AtypIPv6)
		dst = append(dst, v[:]...)
	}
	return append(dst, byte(ap.Port()>>8), byte(ap.Port()))
}

// DecodeAddress parses the SOCKS5 address at the start of b and returns it as "host:port";
// bytes after the address are ignored.
func DecodeAddress(b []byte) (string, error) {
	addr := socks5.SplitAddr(b)
	if addr == nil {
		if len(b) == 0 {
			return "", io.EOF
		}
		return "", fmt.Errorf("invalid address: type %d, %d bytes", b[0], len(b))
	}
	return addr.String(), nil
}
