// Copyright 2011 The Go Authors. All rights reserved.
// Portions of this file are derived from Go's net/interface_windows.go.
// Use of those portions is governed by the BSD-style license in LICENSE-go.

package iface

import (
	"net"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readInterfaceSnapshot avoids calling Interface.Addrs for every adapter:
// Windows implements each such call by enumerating all adapters again.
// Retain the net package's address/metadata semantics. DNS-server and multicast
// address lists are not consumed by this cache, so avoid collecting them.
func readInterfaceSnapshot() ([]interfaceSnapshot, error) {
	var buffer []byte
	size := uint32(15000) // Microsoft-recommended initial allocation.
	for {
		buffer = make([]byte, size)
		const flags = windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_INCLUDE_GATEWAYS |
			windows.GAA_FLAG_SKIP_DNS_SERVER | windows.GAA_FLAG_SKIP_MULTICAST
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
		if err == nil {
			if size == 0 {
				return nil, nil
			}
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buffer)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var result []interfaceSnapshot
	for adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
		result = append(result, snapshotFromAdapter(adapter))
	}
	// All values stored in result own their data; no pointer into buffer escapes.
	runtime.KeepAlive(buffer)
	return result, nil
}

func snapshotFromAdapter(adapter *windows.IpAdapterAddresses) interfaceSnapshot {
	index := adapter.IfIndex
	if index == 0 {
		index = adapter.Ipv6IfIndex
	}
	entry := interfaceSnapshot{Interface: net.Interface{
		Index: int(index),
		MTU:   int(adapter.Mtu),
		Name:  windows.UTF16PtrToString(adapter.FriendlyName),
	}}
	if adapter.Mtu == ^uint32(0) {
		entry.MTU = -1
	}
	if adapter.OperStatus == windows.IfOperStatusUp {
		entry.Flags |= net.FlagUp | net.FlagRunning
	}
	// IANA ifType values used by Go's Windows net.Interface implementation.
	switch adapter.IfType {
	case 6, 9, 71, 144: // Ethernet, token ring, IEEE 802.11, IEEE 1394.
		entry.Flags |= net.FlagBroadcast | net.FlagMulticast
	case 23, 131: // PPP, tunnel.
		entry.Flags |= net.FlagPointToPoint | net.FlagMulticast
	case 24: // Software loopback.
		entry.Flags |= net.FlagLoopback | net.FlagMulticast
	case 37: // ATM.
		entry.Flags |= net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast
	}
	if length := adapter.PhysicalAddressLength; length > 0 && length <= uint32(len(adapter.PhysicalAddress)) {
		entry.HardwareAddr = append(net.HardwareAddr(nil), adapter.PhysicalAddress[:length]...)
	}
	for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
		ip := copySocketIP(address.Address)
		if ip == nil {
			continue
		}
		mask := net.CIDRMask(int(address.OnLinkPrefixLength), len(ip)*8)
		if mask != nil {
			entry.Addrs = append(entry.Addrs, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	for address := adapter.FirstAnycastAddress; address != nil; address = address.Next {
		if ip := copySocketIP(address.Address); ip != nil {
			entry.Addrs = append(entry.Addrs, &net.IPAddr{IP: ip})
		}
	}
	return entry
}

func copySocketIP(address windows.SocketAddress) net.IP {
	if address.Sockaddr == nil || address.SockaddrLength <= 0 {
		return nil
	}
	return append(net.IP(nil), address.IP()...)
}
