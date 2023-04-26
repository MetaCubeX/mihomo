//go:build !windows

package dns

import (
	"fmt"
	"os"
	"regexp"
)

var (
	// nameserver xxx.xxx.xxx.xxx
	nameserverPattern = regexp.MustCompile(`nameserver\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
)

func loadSystemResolver() (clients []dnsClient, err error) {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		err = fmt.Errorf("failed to read /etc/resolv.conf: %w", err)
		return
	}
	nameservers := make([]string, 0)
	for _, line := range nameserverPattern.FindAllStringSubmatch(string(content), -1) {
		addr := line[1]
		nameservers = append(nameservers, addr)
	}
	if len(nameservers) == 0 {
		err = fmt.Errorf("no nameserver found in /etc/resolv.conf")
		return
	}
	servers := make([]NameServer, 0, len(nameservers))
	for _, addr := range nameservers {
		servers = append(servers, NameServer{
			Addr: fmt.Sprintf("%s:%d", addr, 53),
			Net:  "udp",
		})
	}
	return transform(servers, nil), nil
}
