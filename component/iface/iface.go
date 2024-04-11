package iface

import (
	"errors"
	"net"
	"net/netip"
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

func Interfaces() (map[string]*Interface, error) {
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

			ipNets := make([]netip.Prefix, 0, len(addrs))
			for _, addr := range addrs {
				var pf netip.Prefix
				switch ipNet := addr.(type) {
				case *net.IPNet:
					ip, _ := netip.AddrFromSlice(ipNet.IP)
					ones, bits := ipNet.Mask.Size()
					if bits == 32 {
						ip = ip.Unmap()
					}
					pf = netip.PrefixFrom(ip, ones)
				case *net.IPAddr:
					ip, _ := netip.AddrFromSlice(ipNet.IP)
					ip = ip.Unmap()
					pf = netip.PrefixFrom(ip, ip.BitLen())
				}
				if pf.IsValid() {
					ipNets = append(ipNets, pf)
				}
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
	return value, err
}

func ResolveInterface(name string) (*Interface, error) {
	ifaces, err := Interfaces()
	if err != nil {
		return nil, err
	}

	iface, ok := ifaces[name]
	if !ok {
		return nil, ErrIfaceNotFound
	}

	return iface, nil
}

func IsLocalIp(ip netip.Addr) (bool, error) {
	ifaces, err := Interfaces()
	if err != nil {
		return false, err
	}
	for _, iface := range ifaces {
		for _, addr := range iface.Addrs {
			if addr.Contains(ip) {
				return true, nil
			}
		}
	}
	return false, nil
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
