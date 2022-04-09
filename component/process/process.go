package process

import (
	"errors"
	"net"
	"runtime"

	C "github.com/Dreamacro/clash/constant"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")
)

const (
	TCP = "tcp"
	UDP = "udp"
)

func FindProcessName(network string, srcIP net.IP, srcPort int) (string, error) {
	return findProcessName(network, srcIP, srcPort)
}

func ShouldFindProcess(metadata *C.Metadata) bool {
	if runtime.GOOS == "android" {
		return false
	}
	if metadata.Process != "" {
		return false
	}
	for _, ip := range localIPs {
		if ip.Equal(metadata.SrcIP) {
			return true
		}
	}
	return false
}

func AppendLocalIPs(ip ...net.IP) {
	localIPs = append(ip, localIPs...)
}

func getLocalIPs() []net.IP {
	ips := []net.IP{net.IPv4zero, net.IPv6zero}

	netInterfaces, err := net.Interfaces()
	if err != nil {
		ips = append(ips, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
		return ips
	}

	for i := 0; i < len(netInterfaces); i++ {
		if (netInterfaces[i].Flags & net.FlagUp) != 0 {
			adds, _ := netInterfaces[i].Addrs()

			for _, address := range adds {
				if ipNet, ok := address.(*net.IPNet); ok {
					ips = append(ips, ipNet.IP)
				}
			}
		}
	}

	return ips
}

var localIPs []net.IP

func init() {
	localIPs = getLocalIPs()
}
