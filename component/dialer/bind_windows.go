package dialer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/metacubex/mihomo/component/iface"
)

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func bind4(handle syscall.Handle, ifaceIdx int) error {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], uint32(ifaceIdx))
	idx := *(*uint32)(unsafe.Pointer(&bytes[0]))
	err := syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, IP_UNICAST_IF, int(idx))
	if err != nil {
		err = fmt.Errorf("bind4: %w", err)
	}
	return err
}

func bind6(handle syscall.Handle, ifaceIdx int) error {
	err := syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, IPV6_UNICAST_IF, ifaceIdx)
	if err != nil {
		err = fmt.Errorf("bind6: %w", err)
	}
	return err
}

func bindControl(ifaceIdx int, rAddrPort netip.AddrPort) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			handle := syscall.Handle(fd)
			bind6err := bind6(handle, ifaceIdx)
			bind4err := bind4(handle, ifaceIdx)
			switch network {
			case "ip6", "tcp6":
				innerErr = bind6err
			case "ip4", "tcp4", "udp4":
				innerErr = bind4err
			case "udp6":
				// golang will set network to udp6 when listenUDP on wildcard ip (eg: ":0", "")
				if (!addrPort.Addr().IsValid() || addrPort.Addr().IsUnspecified()) && bind6err != nil && rAddrPort.Addr().Unmap().Is4() {
					// try bind ipv6, if failed, ignore. it's a workaround for windows disable interface ipv6
					if bind4err != nil {
						innerErr = fmt.Errorf("%w (%s)", bind6err, bind4err)
					} else {
						innerErr = nil
					}
				} else {
					innerErr = bind6err
				}
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, destination netip.Addr) error {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return err
	}

	addControlToDialer(dialer, bindControl(ifaceObj.Index, netip.AddrPortFrom(destination, 0)))
	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string, rAddrPort netip.AddrPort) (string, error) {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return "", err
	}

	addControlToListenConfig(lc, bindControl(ifaceObj.Index, rAddrPort))
	return address, nil
}

func ParseNetwork(network string, addr netip.Addr) string {
	return network
}
