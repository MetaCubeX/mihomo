package redir

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/Dreamacro/clash/transport/socks5"

	"golang.org/x/sys/unix"
)

const (
	SO_ORIGINAL_DST      = 80 // from linux/include/uapi/linux/netfilter_ipv4.h
	IP6T_SO_ORIGINAL_DST = 80 // from linux/include/uapi/linux/netfilter_ipv6/ip6_tables.h
)

func parserPacket(conn net.Conn) (socks5.Addr, error) {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("only work with TCP connection")
	}

	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	var addr netip.AddrPort

	rc.Control(func(fd uintptr) {
		if ip4 := c.LocalAddr().(*net.TCPAddr).IP.To4(); ip4 != nil {
			addr, err = getorigdst(fd)
		} else {
			addr, err = getorigdst6(fd)
		}
	})

	return socks5.AddrFromStdAddrPort(addr), err
}

// Call getorigdst() from linux/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c
func getorigdst(fd uintptr) (netip.AddrPort, error) {
	addr := unix.RawSockaddrInet4{}
	size := uint32(unsafe.Sizeof(addr))
	if err := socketcall(GETSOCKOPT, fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&addr.Port)))[:])
	return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), port), nil
}

func getorigdst6(fd uintptr) (netip.AddrPort, error) {
	addr := unix.RawSockaddrInet6{}
	size := uint32(unsafe.Sizeof(addr))
	if err := socketcall(GETSOCKOPT, fd, syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&addr.Port)))[:])
	return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr), port), nil
}
