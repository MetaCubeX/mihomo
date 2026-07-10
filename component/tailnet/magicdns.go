package tailnet

import (
	"io"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/utils"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var magicDNS = struct {
	sync.RWMutex
	domains   map[string][]string
	callbacks *utils.Callback[[]string]
}{
	domains:   map[string][]string{},
	callbacks: utils.NewCallback[[]string](),
}

func NormalizeSearchDomains(domains []string) []string {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		domain = strings.TrimRight(domain, ".")
		if domain == "" || domain == "~" {
			continue
		}
		normalized = append(normalized, domain)
	}
	slices.Sort(normalized)
	return slices.Compact(normalized)
}

func SetSearchDomains(proxyName string, domains []string) {
	domains = NormalizeSearchDomains(domains)

	magicDNS.Lock()
	if len(domains) == 0 {
		delete(magicDNS.domains, proxyName)
	} else if slices.Equal(magicDNS.domains[proxyName], domains) {
		magicDNS.Unlock()
		return
	} else {
		magicDNS.domains[proxyName] = domains
	}
	aggregate := searchDomainsLocked()
	magicDNS.Unlock()

	magicDNS.callbacks.Emit(aggregate)
}

func RemoveSearchDomains(proxyName string) {
	SetSearchDomains(proxyName, nil)
}

func SearchDomains() []string {
	magicDNS.RLock()
	defer magicDNS.RUnlock()
	return searchDomainsLocked()
}

func RegisterSearchDomainCallback(callback func([]string)) io.Closer {
	closer := magicDNS.callbacks.Register(callback)
	callback(SearchDomains())
	return closer
}

func ProxyNameForDomain(domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimRight(domain, ".")
	if domain == "" {
		return "", false
	}

	magicDNS.RLock()
	defer magicDNS.RUnlock()

	var (
		bestProxy  string
		bestSuffix string
	)
	for proxyName, domains := range magicDNS.domains {
		for _, suffix := range domains {
			if domain != suffix && !strings.HasSuffix(domain, "."+suffix) {
				continue
			}
			if len(suffix) > len(bestSuffix) {
				bestProxy = proxyName
				bestSuffix = suffix
			}
		}
	}
	return bestProxy, bestProxy != ""
}

func searchDomainsLocked() []string {
	var domains []string
	for _, proxyDomains := range maps.Values(magicDNS.domains) {
		domains = append(domains, proxyDomains...)
	}
	slices.Sort(domains)
	return slices.Compact(domains)
}
