//go:build !windows

package dns

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const resolvConf = "/etc/resolv.conf"

func dnsReadConfig() (servers []string, err error) {
	file, err := os.Open(resolvConf)
	if err != nil {
		err = fmt.Errorf("failed to read %s: %w", resolvConf, err)
		return
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			continue
		}
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			if len(f) > 1 {
				if addr, err := netip.ParseAddr(f[1]); err == nil {
					servers = append(servers, addr.String())
				}
			}
		}
	}
	return
}
