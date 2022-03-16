package iface

import (
	"errors"
	"net"
	"time"

	"github.com/Dreamacro/clash/common/singledo"
)

type Interface struct {
	Index        int
	Name         string
	Addrs        []*net.IPNet
	HardwareAddr net.HardwareAddr
}

var (
	ErrIfaceNotFound = errors.New("interface not found")
	ErrAddrNotFound  = errors.New("addr not found")
)

var interfaces = singledo.NewSingle(time.Second * 20)

func ResolveInterface(name string) (*Interface, error) {
	value, err, _ := interfaces.Do(func() (any, error) {
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

			ipNets := make([]*net.IPNet, 0, len(addrs))
			for _, addr := range addrs {
				ipNet := addr.(*net.IPNet)
				if v4 := ipNet.IP.To4(); v4 != nil {
					ipNet.IP = v4
				}

				ipNets = append(ipNets, ipNet)
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

	ifaces := value.(map[string]*Interface)
	iface, ok := ifaces[name]
	if !ok {
		return nil, ErrIfaceNotFound
	}

	return iface, nil
}

func FlushCache() {
	interfaces.Reset()
}

func (iface *Interface) PickIPv4Addr(destination net.IP) (*net.IPNet, error) {
	return iface.pickIPAddr(destination, func(addr *net.IPNet) bool {
		return addr.IP.To4() != nil
	})
}

func (iface *Interface) PickIPv6Addr(destination net.IP) (*net.IPNet, error) {
	return iface.pickIPAddr(destination, func(addr *net.IPNet) bool {
		return addr.IP.To4() == nil
	})
}

func (iface *Interface) pickIPAddr(destination net.IP, accept func(addr *net.IPNet) bool) (*net.IPNet, error) {
	var fallback *net.IPNet

	for _, addr := range iface.Addrs {
		if !accept(addr) {
			continue
		}

		if fallback == nil && !addr.IP.IsLinkLocalUnicast() {
			fallback = addr

			if destination == nil {
				break
			}
		}

		if destination != nil && addr.Contains(destination) {
			return addr, nil
		}
	}

	if fallback == nil {
		return nil, ErrAddrNotFound
	}

	return fallback, nil
}
