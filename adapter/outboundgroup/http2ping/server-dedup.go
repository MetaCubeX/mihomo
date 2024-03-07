package http2ping

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ReneKroon/ttlcache"
)

var (
	domainPortRegex = regexp.MustCompile(`^(.+):(\d+)$`)
)

type dnsResolvePromise struct {
	ips    []net.IP
	err    error
	doneCh chan struct{}
}

func (d *dnsResolvePromise) Result() ([]net.IP, error) {
	<-d.doneCh
	return d.ips, d.err
}

func (d *dnsResolvePromise) Fulfill(ips []net.IP, err error) {
	d.ips = ips
	d.err = err
	close(d.doneCh)
}

type dnsResolver struct {
	mu    sync.Mutex
	cache *ttlcache.Cache
}

func newDnsResolver() *dnsResolver {
	cache := ttlcache.NewCache()
	cache.SetTTL(time.Second * 60)
	return &dnsResolver{
		cache: cache,
	}
}

func (d *dnsResolver) getCachedPromise(domain string) (*dnsResolvePromise, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := d.cache.Get(domain); ok {
		return v.(*dnsResolvePromise), true
	} else {
		promise := &dnsResolvePromise{
			doneCh: make(chan struct{}),
		}
		d.cache.Set(domain, promise)
		return promise, false
	}
}

func (d *dnsResolver) resolveDomain(domain string) ([]net.IP, error) {
	promise, ok := d.getCachedPromise(domain)
	if ok {
		return promise.Result()
	}
	ips, err := net.LookupIP(domain)
	promise.Fulfill(ips, err)
	if err != nil {
		return nil, fmt.Errorf("lookup ip error: %w", err)
	}
	return ips, nil
}

func (d *dnsResolver) joinIpPorts(ips []net.IP, port string) string {
	var ipPorts []string
	for _, ip := range ips {
		ipPorts = append(ipPorts, fmt.Sprintf("%s:%s", ip.String(), port))
	}
	return strings.Join(ipPorts, ",")
}

func (d *dnsResolver) DomainPortToIpPort(serverDomainPort string) (string, error) {
	matches := domainPortRegex.FindStringSubmatch(serverDomainPort)
	if len(matches) != 3 {
		return "", fmt.Errorf("invalid server domain: %s", serverDomainPort)
	}
	domain, port := matches[1], matches[2]
	ips, err := d.resolveDomain(domain)
	if err != nil {
		return "", err
	}
	return d.joinIpPorts(ips, port), nil
}
