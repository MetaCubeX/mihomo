//go:build windows

package dns

import (
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/exp/slices"
	"golang.org/x/sys/windows"
)

func dnsReadConfig() (servers []string, err error) {
	aas, err := adapterAddresses()
	if err != nil {
		return
	}
	for _, aa := range aas {
		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			sa, err := dns.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}
			var ip net.IP
			switch sa := sa.(type) {
			case *syscall.SockaddrInet4:
				ip = net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
			case *syscall.SockaddrInet6:
				ip = make(net.IP, net.IPv6len)
				copy(ip, sa.Addr[:])
				if ip[0] == 0xfe && ip[1] == 0xc0 {
					// Ignore these fec0/10 ones. Windows seems to
					// populate them as defaults on its misc rando
					// interfaces.
					continue
				}
				//continue
			default:
				// Unexpected type.
				continue
			}
			if slices.Contains(servers, ip.String()) {
				continue
			}
			servers = append(servers, ip.String())
		}
	}
	return
}

// adapterAddresses returns a list of IP adapter and address
// structures. The structure contains an IP adapter and flattened
// multiple IP addresses including unicast, anycast and multicast
// addresses.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
		if l <= uint32(len(b)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}
