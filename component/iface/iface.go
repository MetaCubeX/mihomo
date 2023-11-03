package iface

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
)

type Interface struct {
	Index        int
	Name         string
	Addrs        []netip.Prefix
	HardwareAddr net.HardwareAddr
}

var (
	ErrIfaceNotFound = errors.New("interface not found")
	ErrAddrNotFound  = errors.New("addr not found")
)

var interfaces = singledo.NewSingle[map[string]*Interface](time.Second * 20)

func ResolveInterface(name string) (*Interface, error) {
	value, err, _ := interfaces.Do(func() (map[string]*Interface, error) {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}

		r := map[string]*Interface{}

		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			// if not available device like Meta, dummy0, docker0, etc.
			if (iface.Flags&net.FlagMulticast == 0) || (iface.Flags&net.FlagPointToPoint != 0) || (iface.Flags&net.FlagRunning == 0) {
				continue
			}

			ipNets := make([]netip.Prefix, 0, len(addrs))
			for _, addr := range addrs {
				ipNet := addr.(*net.IPNet)
				ip, _ := netip.AddrFromSlice(ipNet.IP)

				//unavailable IPv6 Address
				if ip.Is6() && strings.HasPrefix(ip.String(), "fe80") {
					continue
				}

				ones, bits := ipNet.Mask.Size()
				if bits == 32 {
					ip = ip.Unmap()
				}

				pf := netip.PrefixFrom(ip, ones)
				ipNets = append(ipNets, pf)
			}

			r[iface.Name] = &Interface{
				Index:        iface.Index,
				Name:         iface.Name,
				Addrs:        ipNets,
				HardwareAddr: iface.HardwareAddr,
			}
		}

		return r, nil
	})
	if err != nil {
		return nil, err
	}

	ifaces := value
	iface, ok := ifaces[name]
	if !ok {
		return nil, ErrIfaceNotFound
	}

	return iface, nil
}

func FlushCache() {
	interfaces.Reset()
}

func (iface *Interface) PickIPv4Addr(destination netip.Addr) (netip.Prefix, error) {
	return iface.pickIPAddr(destination, func(addr netip.Prefix) bool {
		return addr.Addr().Is4()
	})
}

func (iface *Interface) PickIPv6Addr(destination netip.Addr) (netip.Prefix, error) {
	return iface.pickIPAddr(destination, func(addr netip.Prefix) bool {
		return addr.Addr().Is6()
	})
}

func (iface *Interface) pickIPAddr(destination netip.Addr, accept func(addr netip.Prefix) bool) (netip.Prefix, error) {
	var fallback netip.Prefix

	for _, addr := range iface.Addrs {
		if !accept(addr) {
			continue
		}

		if !fallback.IsValid() && !addr.Addr().IsLinkLocalUnicast() {
			fallback = addr

			if !destination.IsValid() {
				break
			}
		}

		if destination.IsValid() && addr.Contains(destination) {
			return addr, nil
		}
	}

	if !fallback.IsValid() {
		return netip.Prefix{}, ErrAddrNotFound
	}

	return fallback, nil
}
