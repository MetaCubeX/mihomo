package dialer

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/Dreamacro/clash/component/iface"
)

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func bind4(handle syscall.Handle, ifaceIdx int) error {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], uint32(ifaceIdx))
	idx := *(*uint32)(unsafe.Pointer(&bytes[0]))
	return syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, IP_UNICAST_IF, int(idx))
}

func bind6(handle syscall.Handle, ifaceIdx int) error {
	return syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, IPV6_UNICAST_IF, ifaceIdx)
}

func bindControl(ifaceIdx int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			handle := syscall.Handle(fd)
			switch network {
			case "tcp6", "udp6":
				innerErr = bind6(handle, ifaceIdx)
				_ = bind4(handle, ifaceIdx)
			default:
				innerErr = bind4(handle, ifaceIdx)
				// try bind ipv6, if failed, ignore. it's a workaround for windows disable interface ipv6
				_ = bind6(handle, ifaceIdx)
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, _ netip.Addr) error {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return err
	}

	addControlToDialer(dialer, bindControl(ifaceObj.Index))
	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string) (string, error) {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return "", err
	}

	addControlToListenConfig(lc, bindControl(ifaceObj.Index))
	return address, nil
}

func ParseNetwork(network string, addr netip.Addr) string {
	return network
}
