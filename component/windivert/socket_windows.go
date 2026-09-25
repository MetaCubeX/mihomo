//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
	tcpTable = ipHelper.NewProc("GetExtendedTcpTable")
	udpTable = ipHelper.NewProc("GetExtendedUdpTable")
)

func socketIndex(key flow) int {
	index := 0
	if key.protocol == 17 {
		index = 2
	}
	if key.source.Addr().Is6() {
		index++
	}
	return index
}

func (t *Tun) socketTable(key flow) (map[flow]uint32, error) {
	ipv6, tcp := key.source.Addr().Is6(), key.protocol == 6
	family := uintptr(windows.AF_INET)
	if ipv6 {
		family = windows.AF_INET6
	}
	proc, class := udpTable, uintptr(1) // UDP_TABLE_OWNER_PID
	if tcp {
		proc, class = tcpTable, 5 // TCP_TABLE_OWNER_PID_ALL, includes SYN_SENT
	}
	size := uint32(len(t.socketBuffer))
	if size < 4096 {
		size = 4096
	}
	for {
		if uint32(len(t.socketBuffer)) < size {
			t.socketBuffer = make([]byte, size)
		}
		code, _, _ := proc.Call(uintptr(unsafe.Pointer(&t.socketBuffer[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if code != 0 {
			return nil, windows.Errno(code)
		}
		index := socketIndex(key)
		t.socketTables[index] = parseSocketTable(t.socketBuffer[:size], key, t.socketTables[index])
		return t.socketTables[index], nil
	}
}

func parseSocketTable(data []byte, key flow, result map[flow]uint32) map[flow]uint32 {
	ipv6, tcp := key.source.Addr().Is6(), key.protocol == 6
	// MIB_{TCP,UDP}{,6}ROW_OWNER_PID from the Windows IP Helper ABI.
	rowSize, ipSize, srcIP, srcPort, dstIP, dstPort, pid := 12, 4, 0, 4, 0, 0, 8
	if tcp {
		rowSize, srcIP, srcPort, dstIP, dstPort, pid = 24, 4, 8, 12, 16, 20
	}
	if ipv6 {
		ipSize, rowSize, srcIP, srcPort, pid = 16, 28, 0, 20, 24
		if tcp {
			rowSize, dstIP, dstPort, pid = 56, 24, 44, 52
		}
	}
	count := int(binary.LittleEndian.Uint32(data))
	if result == nil {
		result = make(map[flow]uint32)
	} else {
		for key := range result {
			delete(result, key)
		}
	}
	for i := 0; i < count; i++ {
		row := data[4+i*rowSize:][:rowSize]
		local, _ := netip.AddrFromSlice(row[srcIP : srcIP+ipSize])
		entry := flow{source: netip.AddrPortFrom(local, binary.BigEndian.Uint16(row[srcPort:])), protocol: key.protocol}
		if tcp {
			remote, _ := netip.AddrFromSlice(row[dstIP : dstIP+ipSize])
			entry.destination = netip.AddrPortFrom(remote, binary.BigEndian.Uint16(row[dstPort:]))
		}
		owner := binary.LittleEndian.Uint32(row[pid:])
		if previous, exists := result[entry]; exists && previous != owner {
			// Shared UDP ports have ambiguous ownership; never redirect them.
			owner = 0
		}
		result[entry] = owner
	}
	return result
}

func socketOwner(entries map[flow]uint32, key flow) uint32 {
	if key.protocol == 6 {
		return entries[key]
	}
	key.destination = netip.AddrPort{}
	owner, exact := entries[key]
	wildcard := netip.IPv4Unspecified()
	if key.source.Addr().Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	key.source = netip.AddrPortFrom(wildcard, key.source.Port())
	if anyOwner, found := entries[key]; found {
		if exact && owner != anyOwner {
			return 0
		}
		owner = anyOwner
	}
	return owner
}
