package sing_tun

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/iface"

	"github.com/metacubex/sing/common/control"
)

type defaultInterfaceFinder struct{}

var DefaultInterfaceFinder control.InterfaceFinder = (*defaultInterfaceFinder)(nil)

func (f *defaultInterfaceFinder) Update() error {
	iface.FlushCache()
	_, err := iface.Interfaces()
	return err
}

func (f *defaultInterfaceFinder) Interfaces() []control.Interface {
	ifaces, err := iface.Interfaces()
	if err != nil {
		return nil
	}
	interfaces := make([]control.Interface, 0, len(ifaces))
	for _, _interface := range ifaces {
		interfaces = append(interfaces, control.Interface(*_interface))
	}

	return interfaces
}

func (f *defaultInterfaceFinder) ByName(name string) (*control.Interface, error) {
	netInterface, err := iface.ResolveInterface(name)
	if err == nil {
		return (*control.Interface)(netInterface), nil
	}
	if _, err := net.InterfaceByName(name); err == nil {
		err = f.Update()
		if err != nil {
			return nil, err
		}
		return f.ByName(name)
	}
	return nil, err
}

func (f *defaultInterfaceFinder) ByIndex(index int) (*control.Interface, error) {
	ifaces, err := iface.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, netInterface := range ifaces {
		if netInterface.Index == index {
			return (*control.Interface)(netInterface), nil
		}
	}
	_, err = net.InterfaceByIndex(index)
	if err == nil {
		err = f.Update()
		if err != nil {
			return nil, err
		}
		return f.ByIndex(index)
	}
	return nil, iface.ErrIfaceNotFound
}

func (f *defaultInterfaceFinder) ByAddr(addr netip.Addr) (*control.Interface, error) {
	netInterface, err := iface.ResolveInterfaceByAddr(addr)
	if err != nil {
		return nil, err
	}
	return (*control.Interface)(netInterface), nil
}
