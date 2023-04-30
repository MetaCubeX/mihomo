//go:build windows

package dns

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	defaultNS = []string{"114.114.114.114:53"}
)

type dnsConfig struct {
	servers []string // server addresses (in host:port form) to use
}

func loadSystemResolver() (clients []dnsClient, err error) {
	content, err := dnsReadConfig()
	if err != nil {
		err = fmt.Errorf("failed to read system DNS: %w", err)
	}
	nameservers := content.servers
	if len(nameservers) == 0 {
		err = fmt.Errorf("no nameserver found in windows system")
		return
	}
	servers := make([]NameServer, 0, len(nameservers))
	for _, addr := range nameservers {
		servers = append(servers, NameServer{
			Addr: addr,
			Net:  "udp",
		})
	}
	return transform(servers, nil), nil
}

func dnsReadConfig() (conf *dnsConfig, err error) {
	conf = &dnsConfig{}
	defer func() {
		if len(conf.servers) == 0 {
			conf.servers = defaultNS
		}
	}()
	aas, err := adapterAddresses()
	if err != nil {
		return conf, err
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
				//ip = make(net.IP, net.IPv6len)
				//copy(ip, sa.Addr[:])
				//if ip[0] == 0xfe && ip[1] == 0xc0 {
				//	// Ignore these fec0/10 ones. Windows seems to
				//	// populate them as defaults on its misc rando
				//	// interfaces.
				//	continue
				//}
				continue
			default:
				// Unexpected type.
				continue
			}
			conf.servers = append(conf.servers, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return conf, nil
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
