//go:build linux

package tproxy

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	IPV6_TRANSPARENT     = 0x4b
	IPV6_RECVORIGDSTADDR = 0x4a
)

// dialUDP acts like net.DialUDP for transparent proxy.
// It binds to a non-local address(`lAddr`).
func dialUDP(network string, lAddr, rAddr netip.AddrPort) (uc *net.UDPConn, err error) {
	rSockAddr, err := udpAddrToSockAddr(rAddr)
	if err != nil {
		return nil, err
	}

	lSockAddr, err := udpAddrToSockAddr(lAddr)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(udpAddrFamily(network, lAddr, rAddr), syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			syscall.Close(fd)
		}
	}()

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return nil, err
	}

	if err = syscall.Bind(fd, lSockAddr); err != nil {
		return nil, err
	}

	if err = syscall.Connect(fd, rSockAddr); err != nil {
		return nil, err
	}

	fdFile := os.NewFile(uintptr(fd), fmt.Sprintf("net-udp-dial-%s", rAddr.String()))
	defer fdFile.Close()

	c, err := net.FileConn(fdFile)
	if err != nil {
		return nil, err
	}

	return c.(*net.UDPConn), nil
}

func udpAddrToSockAddr(addr netip.AddrPort) (syscall.Sockaddr, error) {
	if addr.Addr().Is4() {
		return &syscall.SockaddrInet4{Addr: addr.Addr().As4(), Port: int(addr.Port())}, nil
	}

	zoneID, err := strconv.ParseUint(addr.Addr().Zone(), 10, 32)
	if err != nil {
		zoneID = 0
	}

	return &syscall.SockaddrInet6{Addr: addr.Addr().As16(), Port: int(addr.Port()), ZoneId: uint32(zoneID)}, nil
}

func udpAddrFamily(net string, lAddr, rAddr netip.AddrPort) int {
	switch net[len(net)-1] {
	case '4':
		return syscall.AF_INET
	case '6':
		return syscall.AF_INET6
	}

	if lAddr.Addr().Is4() && rAddr.Addr().Is4() {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func getOrigDst(oob []byte) (netip.AddrPort, error) {
	// oob contains socket control messages which we need to parse.
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse control message: %w", err)
	}

	// retrieve the destination address from the SCM.
	sa, err := unix.ParseOrigDstAddr(&scms[0])
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("retrieve destination: %w", err)
	}

	// encode the destination address into a cmsg.
	var rAddr netip.AddrPort
	switch v := sa.(type) {
	case *unix.SockaddrInet4:
		rAddr = netip.AddrPortFrom(netip.AddrFrom4(v.Addr), uint16(v.Port))
	case *unix.SockaddrInet6:
		rAddr = netip.AddrPortFrom(netip.AddrFrom16(v.Addr), uint16(v.Port))
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported address type: %T", v)
	}

	return rAddr, nil
}
