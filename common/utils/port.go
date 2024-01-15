package utils

import (
	"net"
	"strconv"
	"strings"
)

// parsePorts parses the multi-port server address and returns the port slice.
// Supports both comma-separated single ports and dash-separated port ranges.
// Format: "port1,port2-port3,port4"
func ParsePorts(serverPorts string) (ports []uint16, err error) {
	portStrs := strings.Split(serverPorts, ",")
	for _, portStr := range portStrs {
		if strings.Contains(portStr, "-") {
			// Port range
			portRange := strings.Split(portStr, "-")
			if len(portRange) != 2 {
				return nil, net.InvalidAddrError("invalid port range")
			}
			start, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return nil, net.InvalidAddrError("invalid port range")
			}
			end, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return nil, net.InvalidAddrError("invalid port range")
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				ports = append(ports, uint16(i))
			}
		} else {
			// Single port
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil, net.InvalidAddrError("invalid port")
			}
			ports = append(ports, uint16(port))
		}
	}
	if len(ports) == 0 {
		return nil, net.InvalidAddrError("invalid port")
	}
	return ports, nil
}
