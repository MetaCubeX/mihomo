package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/fakeip"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"

	D "github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type dnsClient interface {
	Exchange(m *D.Msg) (msg *D.Msg, err error)
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
}

type result struct {
	Msg   *D.Msg
	Error error
}

type Resolver struct {
	ipv6                  bool
	hosts                 *trie.DomainTrie
	main                  []dnsClient
	fallback              []dnsClient
	fallbackDomainFilters []fallbackDomainFilter
	fallbackIPFilters     []fallbackIPFilter
	group                 singleflight.Group
	lruCache              *cache.LruCache
	policy                *trie.DomainTrie
}

// LookupIP request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) LookupIP(ctx context.Context, host string) (ip []net.IP, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan []net.IP, 1)

	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ip, err = r.lookupIP(ctx, host, D.TypeA)
	if err == nil {
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

// ResolveIP request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) ResolveIP(host string) (ip net.IP, err error) {
	ips, err := r.LookupIP(context.Background(), host)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// ResolveIPv4 request with TypeA
func (r *Resolver) ResolveIPv4(host string) (ip net.IP, err error) {
	ips, err := r.lookupIP(context.Background(), host, D.TypeA)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

// ResolveIPv6 request with TypeAAAA
func (r *Resolver) ResolveIPv6(host string) (ip net.IP, err error) {
	ips, err := r.lookupIP(context.Background(), host, D.TypeAAAA)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

func (r *Resolver) shouldIPFallback(ip net.IP) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.Match(ip) {
			return true
		}
	}
	return false
}

// Exchange a batch of dns request, and it use cache
func (r *Resolver) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return r.ExchangeContext(context.Background(), m)
}

// ExchangeContext a batch of dns request with context.Context, and it use cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if len(m.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}

	q := m.Question[0]
	cache, expireTime, hit := r.lruCache.GetWithExpire(q.String())
	if hit {
		now := time.Now()
		msg = cache.(*D.Msg).Copy()
		if expireTime.Before(now) {
			setMsgTTL(msg, uint32(1)) // Continue fetch
			go r.exchangeWithoutCache(ctx, m)
		} else {
			setMsgTTL(msg, uint32(time.Until(expireTime).Seconds()))
		}
		return
	}
	return r.exchangeWithoutCache(ctx, m)
}

// ExchangeWithoutCache a batch of dns request, and it do NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	q := m.Question[0]

	ret, err, shared := r.group.Do(q.String(), func() (result any, err error) {
		defer func() {
			if err != nil {
				return
			}

			msg := result.(*D.Msg)

			putMsgToCache(r.lruCache, q.String(), msg)
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			return r.ipExchange(ctx, m)
		}

		if matched := r.matchPolicy(m); len(matched) != 0 {
			return r.batchExchange(ctx, matched, m)
		}
		return r.batchExchange(ctx, r.main, m)
	})

	if err == nil {
		msg = ret.(*D.Msg)
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *D.Msg, err error) {
	ctx, cancel := context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
	defer cancel()

	return batchExchange(ctx, clients, m)
}

func (r *Resolver) matchPolicy(m *D.Msg) []dnsClient {
	if r.policy == nil {
		return nil
	}

	domain := r.msgToDomain(m)
	if domain == "" {
		return nil
	}

	record := r.policy.Search(domain)
	if record == nil {
		return nil
	}

	return record.Data.([]dnsClient)
}

func (r *Resolver) shouldOnlyQueryFallback(m *D.Msg) bool {
	if r.fallback == nil || len(r.fallbackDomainFilters) == 0 {
		return false
	}

	domain := r.msgToDomain(m)

	if domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.Match(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if matched := r.matchPolicy(m); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, res.Error
	}

	onlyFallback := r.shouldOnlyQueryFallback(m)

	if onlyFallback {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	fallbackMsg := r.asyncExchange(ctx, r.fallback, m)
	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			if !r.shouldIPFallback(ips[0]) {
				msg = res.Msg // no need to wait for fallback result
				err = res.Error
				return msg, err
			}
		}
	}

	res = <-fallbackMsg
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) ([]net.IP, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		ip4 := ip.To4()
		isIPv4 := ip4 != nil
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []net.IP{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []net.IP{ip4}, nil
		} else {
			return nil, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.Exchange(query)
	if err != nil {
		return nil, err
	}

	ips := msgToIP(msg)
	if len(ips) == 0 {
		return nil, resolver.ErrIPNotFound
	}
	return ips, nil
}

func (r *Resolver) msgToDomain(msg *D.Msg) string {
	if len(msg.Question) > 0 {
		return strings.TrimRight(msg.Question[0].Name, ".")
	}

	return ""
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, err := r.batchExchange(ctx, client, msg)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

type NameServer struct {
	Net       string
	Addr      string
	Interface string
}

type FallbackFilter struct {
	GeoIP     bool
	GeoIPCode string
	IPCIDR    []*net.IPNet
	Domain    []string
}

type Config struct {
	Main, Fallback []NameServer
	Default        []NameServer
	IPv6           bool
	EnhancedMode   C.DNSMode
	FallbackFilter FallbackFilter
	Pool           *fakeip.Pool
	Hosts          *trie.DomainTrie
	Policy         map[string]NameServer
}

func NewResolver(config Config) *Resolver {
	defaultResolver := &Resolver{
		main:     transform(config.Default, nil),
		lruCache: cache.New(cache.WithSize(4096), cache.WithStale(true)),
	}

	r := &Resolver{
		ipv6:     config.IPv6,
		main:     transform(config.Main, defaultResolver),
		lruCache: cache.New(cache.WithSize(4096), cache.WithStale(true)),
		hosts:    config.Hosts,
	}

	if len(config.Fallback) != 0 {
		r.fallback = transform(config.Fallback, defaultResolver)
	}

	if len(config.Policy) != 0 {
		r.policy = trie.New()
		for domain, nameserver := range config.Policy {
			r.policy.Insert(domain, transform([]NameServer{nameserver}, defaultResolver))
		}
	}

	fallbackIPFilters := []fallbackIPFilter{}
	if config.FallbackFilter.GeoIP {
		fallbackIPFilters = append(fallbackIPFilters, &geoipFilter{
			code: config.FallbackFilter.GeoIPCode,
		})
	}
	for _, ipnet := range config.FallbackFilter.IPCIDR {
		fallbackIPFilters = append(fallbackIPFilters, &ipnetFilter{ipnet: ipnet})
	}
	r.fallbackIPFilters = fallbackIPFilters

	if len(config.FallbackFilter.Domain) != 0 {
		fallbackDomainFilters := []fallbackDomainFilter{NewDomainFilter(config.FallbackFilter.Domain)}
		r.fallbackDomainFilters = fallbackDomainFilters
	}

	return r
}
