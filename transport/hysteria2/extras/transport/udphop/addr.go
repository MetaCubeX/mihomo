package udphop

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type InvalidPortError struct {
	PortStr string
}

func (e InvalidPortError) Error() string {
	return fmt.Sprintf("%s is not a valid port number or range", e.PortStr)
}

// UDPHopAddr contains an IP address and a list of ports.
type UDPHopAddr struct {
	IP      net.IP
	Ports   []uint16
	PortStr string
}

func (a *UDPHopAddr) Network() string {
	return "udphop"
}

func (a *UDPHopAddr) String() string {
	return net.JoinHostPort(a.IP.String(), a.PortStr)
}

// addrs returns a list of net.Addr's, one for each port.
func (a *UDPHopAddr) addrs() ([]net.Addr, error) {
	var addrs []net.Addr
	for _, port := range a.Ports {
		addr := &net.UDPAddr{
			IP:   a.IP,
			Port: int(port),
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func ResolveUDPHopAddr(addr string) (*UDPHopAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}
	result := &UDPHopAddr{
		IP:      ip.IP,
		PortStr: portStr,
	}

	portStrs := strings.Split(portStr, ",")
	for _, portStr := range portStrs {
		if strings.Contains(portStr, "-") {
			// Port range
			portRange := strings.Split(portStr, "-")
			if len(portRange) != 2 {
				return nil, InvalidPortError{portStr}
			}
			start, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return nil, InvalidPortError{portStr}
			}
			end, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return nil, InvalidPortError{portStr}
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				result.Ports = append(result.Ports, uint16(i))
			}
		} else {
			// Single port
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil, InvalidPortError{portStr}
			}
			result.Ports = append(result.Ports, uint16(port))
		}
	}
	return result, nil
}
