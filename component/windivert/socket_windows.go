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
		return parseSocketTable(t.socketBuffer[:size], key), nil
	}
}

func parseSocketTable(data []byte, key flow) map[flow]uint32 {
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
	result := make(map[flow]uint32)
	for i := 0; i < count; i++ {
		row := data[4+i*rowSize:][:rowSize]
		local, _ := netip.AddrFromSlice(row[srcIP : srcIP+ipSize])
		entry := flow{source: netip.AddrPortFrom(local, binary.BigEndian.Uint16(row[srcPort:])), protocol: key.protocol}
		if tcp {
			remote, _ := netip.AddrFromSlice(row[dstIP : dstIP+ipSize])
			entry.destination = netip.AddrPortFrom(remote, binary.BigEndian.Uint16(row[dstPort:]))
		} else {
			if entry.source.Port() != key.source.Port() || (local != key.source.Addr() && !local.IsUnspecified()) {
				continue
			}
			entry = key
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
