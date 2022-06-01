package process

import (
	"errors"
	"github.com/Dreamacro/clash/common/nnip"
	C "github.com/Dreamacro/clash/constant"
	"net"
	"net/netip"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")

	enableFindProcess = true
)

const (
	TCP = "tcp"
	UDP = "udp"
)

func EnableFindProcess(e bool) {
	enableFindProcess = e
}

func FindProcessName(network string, srcIP netip.Addr, srcPort int) (int32, string, error) {
	return findProcessName(network, srcIP, srcPort)
}

func FindUid(network string, srcIP netip.Addr, srcPort int) (int32, error) {
	_, uid, err := resolveSocketByNetlink(network, srcIP, srcPort)
	if err != nil {
		return -1, err
	}
	return uid, nil
}

func ShouldFindProcess(metadata *C.Metadata) bool {
	if !enableFindProcess ||
		metadata.Process != "" ||
		metadata.ProcessPath != "" {
		return false
	}
	for _, ip := range localIPs {
		if ip == metadata.SrcIP {
			return true
		}
	}
	return false
}

func AppendLocalIPs(ip ...netip.Addr) {
	localIPs = append(ip, localIPs...)
}

func getLocalIPs() []netip.Addr {
	ips := []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}

	netInterfaces, err := net.Interfaces()
	if err != nil {
		ips = append(ips, netip.AddrFrom4([4]byte{127, 0, 0, 1}), nnip.IpToAddr(net.IPv6loopback))
		return ips
	}

	for i := 0; i < len(netInterfaces); i++ {
		if (netInterfaces[i].Flags & net.FlagUp) != 0 {
			adds, _ := netInterfaces[i].Addrs()

			for _, address := range adds {
				if ipNet, ok := address.(*net.IPNet); ok {
					ips = append(ips, nnip.IpToAddr(ipNet.IP))
				}
			}
		}
	}

	return ips
}

var localIPs []netip.Addr

func init() {
	localIPs = getLocalIPs()
}
