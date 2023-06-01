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

func dnsReadConfig() (servers []string, err error) {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		err = fmt.Errorf("failed to read /etc/resolv.conf: %w", err)
		return
	}
	for _, line := range nameserverPattern.FindAllStringSubmatch(string(content), -1) {
		addr := line[1]
		servers = append(servers, addr)
	}
	return
}
