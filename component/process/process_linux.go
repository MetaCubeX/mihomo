package process

import (
	"fmt"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"net/netip"
)

func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
	uid, err := resolveSocketUID(ip, srcPort)
	if err != nil {
		return 0, "", err
	}
	name, err := resolveProcessNameByUID(uid)
	return uid, name, err
}

func resolveSocketUID(ip netip.Addr, srcPort int) (uint32, error) {
	connections, err := net.Connections("all")
	if err != nil {
		return 0, err
	}

	for _, conn := range connections {
		if conn.Laddr.Port == uint32(srcPort) && conn.Laddr.IP == ip.String() {
			if len(conn.Uids) > 0 {
				return uint32(conn.Uids[0]), nil
			}
		}
	}
	return 0, ErrNotFound
}

func resolveProcessNameByUID(uid uint32) (string, error) {
	processes, err := process.Processes()
	if err != nil {
		return "", err
	}

	for _, p := range processes {
		puid, err := p.Uids()
		if err == nil && len(puid) > 0 && uint32(puid[0]) == uid {
			name, err := p.Name()
			if err != nil {
				continue
			}
			return name, nil
		}
	}
	return "", fmt.Errorf("process of uid(%d) not found", uid)
}
