//go:build android && cmfa

package dns

import (
	"github.com/metacubex/mihomo/component/resolver"
)

var systemResolver []dnsClient

func FlushCacheWithDefaultResolver() {
	if r := resolver.DefaultResolver; r != nil {
		r.ClearCache()
	}
}

func UpdateSystemDNS(addr []string) {
	if len(addr) == 0 {
		systemResolver = nil
	}

	ns := make([]NameServer, 0, len(addr))
	for _, d := range addr {
		ns = append(ns, NameServer{Addr: d})
	}

	systemResolver = transform(ns, nil)
}

func (c *systemClient) getDnsClients() ([]dnsClient, error) {
	return systemResolver, nil
}
