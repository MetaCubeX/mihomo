package sing_tun

import (
	"errors"
	"net/netip"

	"github.com/metacubex/mihomo/component/iface"

	"github.com/sagernet/sing/common/control"
)

type defaultInterfaceFinder struct{}

var DefaultInterfaceFinder control.InterfaceFinder = (*defaultInterfaceFinder)(nil)

func (f *defaultInterfaceFinder) Update() error {
	iface.FlushCache()
	return nil
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

var errNoSuchInterface = errors.New("no such network interface")

func (f *defaultInterfaceFinder) InterfaceIndexByName(name string) (int, error) {
	ifaces, err := iface.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, netInterface := range ifaces {
		if netInterface.Name == name {
			return netInterface.Index, nil
		}
	}
	return 0, errNoSuchInterface
}

func (f *defaultInterfaceFinder) InterfaceNameByIndex(index int) (string, error) {
	ifaces, err := iface.Interfaces()
	if err != nil {
		return "", err
	}
	for _, netInterface := range ifaces {
		if netInterface.Index == index {
			return netInterface.Name, nil
		}
	}
	return "", errNoSuchInterface
}

func (f *defaultInterfaceFinder) InterfaceByAddr(addr netip.Addr) (*control.Interface, error) {
	ifaces, err := iface.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, netInterface := range ifaces {
		for _, prefix := range netInterface.Addresses {
			if prefix.Contains(addr) {
				return (*control.Interface)(netInterface), nil
			}
		}
	}
	return nil, errNoSuchInterface
}
