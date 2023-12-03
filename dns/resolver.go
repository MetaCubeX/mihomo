package dns

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/arc"
	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/singleflight"
)

type dnsClient interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
	Address() string
}

type dnsCache interface {
	GetWithExpire(key string) (*D.Msg, time.Time, bool)
	SetWithExpire(key string, value *D.Msg, expire time.Time)
}

type result struct {
	Msg   *D.Msg
	Error error
}

type Resolver struct {
	ipv6                  bool
	ipv6Timeout           time.Duration
	hosts                 *trie.DomainTrie[resolver.HostValue]
	main                  []dnsClient
	fallback              []dnsClient
	fallbackDomainFilters []fallbackDomainFilter
	fallbackIPFilters     []fallbackIPFilter
	group                 singleflight.Group
	cache                 dnsCache
	policy                []dnsPolicy
	proxyServer           []dnsClient
}

func (r *Resolver) LookupIPPrimaryIPv4(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	if err == nil {
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

func (r *Resolver) LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}

		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	var waitIPv6 *time.Timer
	if r != nil && r.ipv6Timeout > 0 {
		waitIPv6 = time.NewTimer(r.ipv6Timeout)
	} else {
		waitIPv6 = time.NewTimer(100 * time.Millisecond)
	}
	defer waitIPv6.Stop()
	select {
	case ipv6s, open := <-ch:
		if !open && err != nil {
			return nil, resolver.ErrIPNotFound
		}
		ips = append(ips, ipv6s...)
	case <-waitIPv6.C:
		// wait ipv6 result
	}

	return ips, nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.Match(ip) {
			return true
		}
	}
	return false
}

// ExchangeContext a batch of dns request with context.Context, and it use cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if len(m.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	continueFetch := false
	defer func() {
		if continueFetch || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
				defer cancel()
				_, _ = r.exchangeWithoutCache(ctx, m) // ignore result, just for putMsgToCache
			}()
		}
	}()

	q := m.Question[0]
	cacheM, expireTime, hit := r.cache.GetWithExpire(q.String())
	if hit {
		log.Debugln("[DNS] cache hit for %s, expire at %s", q.Name, expireTime.Format("2006-01-02 15:04:05"))
		now := time.Now()
		msg = cacheM.Copy()
		if expireTime.Before(now) {
			setMsgTTL(msg, uint32(1)) // Continue fetch
			continueFetch = true
		} else {
			// updating TTL by subtracting common delta time from each DNS record
			updateMsgTTL(msg, uint32(time.Until(expireTime).Seconds()))
		}
		return
	}
	return r.exchangeWithoutCache(ctx, m)
}

// ExchangeWithoutCache a batch of dns request, and it do NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	q := m.Question[0]

	retryNum := 0
	retryMax := 3
	fn := func() (result any, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout) // reset timeout in singleflight
		defer cancel()
		cache := false

		defer func() {
			if err != nil {
				result = retryNum
				retryNum++
				return
			}

			msg := result.(*D.Msg)

			if cache {
				// OPT RRs MUST NOT be cached, forwarded, or stored in or loaded from master files.
				msg.Extra = lo.Filter(msg.Extra, func(rr D.RR, index int) bool {
					return rr.Header().Rrtype != D.TypeOPT
				})
				putMsgToCache(r.cache, q.String(), q, msg)
			}
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			cache = true
			return r.ipExchange(ctx, m)
		}

		if matched := r.matchPolicy(m); len(matched) != 0 {
			result, cache, err = batchExchange(ctx, matched, m)
			return
		}
		result, cache, err = batchExchange(ctx, r.main, m)
		return
	}

	ch := r.group.DoChan(q.String(), fn)

	var result singleflight.Result

	select {
	case result = <-ch:
		break
	case <-ctx.Done():
		select {
		case result = <-ch: // maybe ctxDone and chFinish in same time, get DoChan's result as much as possible
			break
		default:
			go func() { // start a retrying monitor in background
				result := <-ch
				ret, err, shared := result.Val, result.Err, result.Shared
				if err != nil && !shared && ret.(int) < retryMax { // retry
					r.group.DoChan(q.String(), fn)
				}
			}()
			return nil, ctx.Err()
		}
	}

	ret, err, shared := result.Val, result.Err, result.Shared
	if err != nil && !shared && ret.(int) < retryMax { // retry
		r.group.DoChan(q.String(), fn)
	}

	if err == nil {
		msg = ret.(*D.Msg)
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) matchPolicy(m *D.Msg) []dnsClient {
	if r.policy == nil {
		return nil
	}

	domain := msgToDomain(m)
	if domain == "" {
		return nil
	}

	for _, policy := range r.policy {
		if dnsClients := policy.Match(domain); len(dnsClients) > 0 {
			return dnsClients
		}
	}
	return nil
}

func (r *Resolver) shouldOnlyQueryFallback(m *D.Msg) bool {
	if r.fallback == nil || len(r.fallbackDomainFilters) == 0 {
		return false
	}

	domain := msgToDomain(m)

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

	if r.fallback == nil || len(r.fallback) == 0 { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			shouldNotFallback := lo.EveryBy(ips, func(ip netip.Addr) bool {
				return !r.shouldIPFallback(ip)
			})
			if shouldNotFallback {
				msg, err = res.Msg, res.Error // no need to wait for fallback result
				return
			}
		}
	}

	res = <-r.asyncExchange(ctx, r.fallback, m)
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) (ips []netip.Addr, err error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return []netip.Addr{}, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return []netip.Addr{}, err
	}

	ips = msgToIP(msg)
	ipLength := len(ips)
	if ipLength == 0 {
		return []netip.Addr{}, resolver.ErrIPNotFound
	}

	return
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, _, err := batchExchange(ctx, client, msg)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

// Invalid return this resolver can or can't be used
func (r *Resolver) Invalid() bool {
	if r == nil {
		return false
	}
	return len(r.main) > 0
}

type NameServer struct {
	Net          string
	Addr         string
	Interface    string
	ProxyAdapter C.ProxyAdapter
	ProxyName    string
	Params       map[string]string
	PreferH3     bool
}

func (ns NameServer) Equal(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	if ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.Interface == ns2.Interface &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		maps.Equal(ns.Params, ns2.Params) &&
		ns.PreferH3 == ns2.PreferH3 {
		return true
	}
	return false
}

type FallbackFilter struct {
	GeoIP     bool
	GeoIPCode string
	IPCIDR    []netip.Prefix
	Domain    []string
	GeoSite   []*router.DomainMatcher
}

type Config struct {
	Main, Fallback []NameServer
	Default        []NameServer
	ProxyServer    []NameServer
	IPv6           bool
	IPv6Timeout    uint
	EnhancedMode   C.DNSMode
	FallbackFilter FallbackFilter
	Pool           *fakeip.Pool
	Hosts          *trie.DomainTrie[resolver.HostValue]
	Policy         *orderedmap.OrderedMap[string, []NameServer]
	RuleProviders  map[string]provider.RuleProvider
	CacheAlgorithm string
}

func NewResolver(config Config) *Resolver {
	var cache dnsCache
	if config.CacheAlgorithm == "lru" {
		cache = lru.New(lru.WithSize[string, *D.Msg](4096), lru.WithStale[string, *D.Msg](true))
	} else {
		cache = arc.New(arc.WithSize[string, *D.Msg](4096))
	}
	defaultResolver := &Resolver{
		main:        transform(config.Default, nil),
		cache:       cache,
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
	}

	var nameServerCache []struct {
		NameServer
		dnsClient
	}
	cacheTransform := func(nameserver []NameServer) (result []dnsClient) {
	LOOP:
		for _, ns := range nameserver {
			for _, nsc := range nameServerCache {
				if nsc.NameServer.Equal(ns) {
					result = append(result, nsc.dnsClient)
					continue LOOP
				}
			}
			// not in cache
			dc := transform([]NameServer{ns}, defaultResolver)
			if len(dc) > 0 {
				dc := dc[0]
				nameServerCache = append(nameServerCache, struct {
					NameServer
					dnsClient
				}{NameServer: ns, dnsClient: dc})
				result = append(result, dc)
			}
		}
		return
	}

	if config.CacheAlgorithm == "" || config.CacheAlgorithm == "lru" {
		cache = lru.New(lru.WithSize[string, *D.Msg](4096), lru.WithStale[string, *D.Msg](true))
	} else {
		cache = arc.New(arc.WithSize[string, *D.Msg](4096))
	}
	r := &Resolver{
		ipv6:        config.IPv6,
		main:        cacheTransform(config.Main),
		cache:       cache,
		hosts:       config.Hosts,
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
	}

	if len(config.Fallback) != 0 {
		r.fallback = cacheTransform(config.Fallback)
	}

	if len(config.ProxyServer) != 0 {
		r.proxyServer = cacheTransform(config.ProxyServer)
	}

	if config.Policy.Len() != 0 {
		r.policy = make([]dnsPolicy, 0)

		var triePolicy *trie.DomainTrie[[]dnsClient]
		insertTriePolicy := func() {
			if triePolicy != nil {
				triePolicy.Optimize()
				r.policy = append(r.policy, domainTriePolicy{triePolicy})
				triePolicy = nil
			}
		}

		for pair := config.Policy.Oldest(); pair != nil; pair = pair.Next() {
			domain, nameserver := pair.Key, pair.Value
			domain = strings.ToLower(domain)

			if temp := strings.Split(domain, ":"); len(temp) == 2 {
				prefix := temp[0]
				key := temp[1]
				switch strings.ToLower(prefix) {
				case "rule-set":
					if p, ok := config.RuleProviders[key]; ok {
						insertTriePolicy()
						r.policy = append(r.policy, domainSetPolicy{
							domainSetProvider: p,
							dnsClients:        cacheTransform(nameserver),
						})
						continue
					} else {
						log.Warnln("can't found ruleset policy: %s", key)
					}
				case "geosite":
					inverse := false
					if strings.HasPrefix(key, "!") {
						inverse = true
						key = key[1:]
					}
					log.Debugln("adding geosite policy: %s inversed %t", key, inverse)
					matcher, err := NewGeoSite(key)
					if err != nil {
						log.Warnln("adding geosite policy %s error: %s", key, err)
						continue
					}
					insertTriePolicy()
					r.policy = append(r.policy, geositePolicy{
						matcher:    matcher,
						inverse:    inverse,
						dnsClients: cacheTransform(nameserver),
					})
					continue // skip triePolicy new
				}
			}
			if triePolicy == nil {
				triePolicy = trie.New[[]dnsClient]()
			}
			_ = triePolicy.Insert(domain, cacheTransform(nameserver))
		}
		insertTriePolicy()
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

	fallbackDomainFilters := []fallbackDomainFilter{}
	if len(config.FallbackFilter.Domain) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, NewDomainFilter(config.FallbackFilter.Domain))
	}

	if len(config.FallbackFilter.GeoSite) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, &geoSiteFilter{
			matchers: config.FallbackFilter.GeoSite,
		})
	}
	r.fallbackDomainFilters = fallbackDomainFilters

	return r
}

func NewProxyServerHostResolver(old *Resolver) *Resolver {
	r := &Resolver{
		ipv6:        old.ipv6,
		main:        old.proxyServer,
		cache:       old.cache,
		hosts:       old.hosts,
		ipv6Timeout: old.ipv6Timeout,
	}
	return r
}

var ParseNameServer func(servers []string) ([]NameServer, error) // define in config/config.go
