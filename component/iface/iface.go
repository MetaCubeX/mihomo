package iface

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/common/singledo"

	"github.com/metacubex/bart"
)

type Interface struct {
	Index        int
	MTU          int
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	Addresses    []netip.Prefix
}

var (
	ErrIfaceNotFound = errors.New("interface not found")
	ErrAddrNotFound  = errors.New("addr not found")
)

type ifaceCache struct {
	ifMapByName map[string]*Interface
	ifMapByAddr map[netip.Addr]*Interface
	ifTable     bart.Table[*Interface]
}

var caches = singledo.NewSingle[*ifaceCache](time.Second * 20)

func getCache() (*ifaceCache, error) {
	value, err, _ := caches.Do(func() (*ifaceCache, error) {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}

		cache := &ifaceCache{
			ifMapByName: make(map[string]*Interface),
			ifMapByAddr: make(map[netip.Addr]*Interface),
		}

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

			ifaceObj := &Interface{
				Index:        iface.Index,
				MTU:          iface.MTU,
				Name:         iface.Name,
				HardwareAddr: iface.HardwareAddr,
				Flags:        iface.Flags,
				Addresses:    ipNets,
			}
			cache.ifMapByName[iface.Name] = ifaceObj

			if iface.Flags&net.FlagUp == 0 {
				continue // interface down
			}
			for _, prefix := range ipNets {
				cache.ifMapByAddr[prefix.Addr()] = ifaceObj
				cache.ifTable.Insert(prefix, ifaceObj)
			}
		}

		return cache, nil
	})
	return value, err
}

func Interfaces() (map[string]*Interface, error) {
	cache, err := getCache()
	if err != nil {
		return nil, err
	}
	return cache.ifMapByName, nil
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

func ResolveInterfaceByAddr(addr netip.Addr) (*Interface, error) {
	cache, err := getCache()
	if err != nil {
		return nil, err
	}
	// maybe two interfaces have the same prefix but different address
	// so direct check address equal before do a route lookup (longest prefix match)
	if iface, ok := cache.ifMapByAddr[addr]; ok {
		return iface, nil
	}
	iface, ok := cache.ifTable.Lookup(addr)
	if !ok {
		return nil, ErrIfaceNotFound
	}

	return iface, nil
}

func IsLocalIp(addr netip.Addr) (bool, error) {
	cache, err := getCache()
	if err != nil {
		return false, err
	}
	_, ok := cache.ifMapByAddr[addr]
	return ok, nil
}

func FlushCache() {
	caches.Reset()
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

	for _, addr := range iface.Addresses {
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
