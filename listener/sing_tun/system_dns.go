package sing_tun

import "github.com/metacubex/mihomo/component/tailnet"

func systemDNSSearchDomainArgs(tunName string, searchDomains []string) []string {
	args := []string{"domain", tunName, "~."}
	return append(args, tailnet.NormalizeSearchDomains(searchDomains)...)
}
