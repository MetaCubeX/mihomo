//go:build !windows

package iface

import "github.com/metacubex/mihomo/component/iface/anet"

func readInterfaceSnapshot() ([]interfaceSnapshot, error) {
	interfaces, err := anet.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]interfaceSnapshot, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses, err := anet.InterfaceAddrsByInterface(&iface)
		if err != nil {
			continue
		}
		result = append(result, interfaceSnapshot{Interface: iface, Addrs: addresses})
	}
	return result, nil
}
