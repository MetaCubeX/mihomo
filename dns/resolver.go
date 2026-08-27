package dns

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/arc"
	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
)

type dnsClient interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
	Address() string
	ResetConnection()
}

type dnsCache interface {
	GetWithExpire(key string) (*D.Msg, time.Time, bool)
	SetWithExpire(key string, value *D.Msg, expire time.Time)
	Clear()
}

type result struct {
	Msg   *D.Msg
	Error error
}

const fallbackCircuitMaxDomains = 4096

type fallbackScope uint8

const (
	fallbackScopeNone fallbackScope = iota
	fallbackScopeDomain
	fallbackScopeGroup
)

type fallbackCircuit struct {
	mu              sync.Mutex
	groupUntil      time.Time
	domains         *lru.LruCache[string, time.Time]
	interval        time.Duration
	probeRunning    bool
	probeGeneration uint64
	probeCancel     context.CancelFunc
}

func newFallbackCircuit(interval time.Duration) *fallbackCircuit {
	if interval <= 0 {
		return nil
	}
	return &fallbackCircuit{
		domains:  lru.New(lru.WithSize[string, time.Time](fallbackCircuitMaxDomains)),
		interval: interval,
	}
}

type Resolver struct {
	ipv6                  bool
	ipv6Timeout           time.Duration
	main                  []dnsClient
	fallback              []dnsClient
	fallbackDomainFilters []C.DomainMatcher
	fallbackIPFilters     []C.IpMatcher
	fallbackLazyQuery     bool
	fallbackTimeout       time.Duration
	delayedFallback       bool
	fallbackCircuit       *fallbackCircuit
	fallbackLabel         string
	group                 singleflight.Group[*D.Msg]
	cache                 dnsCache
	policy                []dnsPolicy
	defaultResolver       *Resolver
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
		if filter.MatchIp(ip) {
			return true
		}
	}
	return false
}

func (r *Resolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), D.TypeHTTPS)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	for _, rr := range msg.Answer {
		switch resource := rr.(type) {
		case *D.HTTPS:
			for _, value := range resource.Value {
				if echConfig, ok := value.(*D.SVCBECHConfig); ok {
					return echConfig.ECH, nil
				}
			}
		}
	}
	return nil, errors.New("no ECH config found in DNS records")
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
	domain := msgToDomain(m)
	msg, expireTime, hit := getMsgFromCache(r.cache, q)
	if hit {
		log.Debugln("[DNS] cache hit %s --> %s, expire at %s", domain, msgToLogString(msg), expireTime.Format("2006-01-02 15:04:05"))
		now := time.Now()
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
	fn := func() (result *D.Msg, err error) {
		queryTimeout := resolver.DefaultDNSTimeout
		if r.delayedFallback {
			queryTimeout = 2 * r.fallbackQueryTimeout()
		}
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout) // reset timeout in singleflight
		defer cancel()
		cache := false

		defer func() {
			if err != nil {
				result = &D.Msg{}
				result.Opcode = retryNum
				retryNum++
				return
			}

			if cache {
				putMsgToCache(r.cache, q, result)
			}
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			result, cache, err = r.ipExchange(ctx, m)
			return
		}

		if matched := r.matchPolicy(m); len(matched) != 0 {
			result, cache, err = batchExchange(ctx, matched, m)
			return
		}
		result, cache, err = batchExchange(ctx, r.main, m)
		return
	}

	ch := r.group.DoChan(q.String(), fn)

	var result singleflight.Result[*D.Msg]

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
				if err != nil && !shared && ret.Opcode < retryMax { // retry
					r.group.DoChan(q.String(), fn)
				}
			}()
			return nil, ctx.Err()
		}
	}

	ret, err, shared := result.Val, result.Err, result.Shared
	if err != nil && !shared && ret.Opcode < retryMax { // retry
		r.group.DoChan(q.String(), fn)
	}

	if err == nil {
		msg = ret
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
		if df.MatchDomain(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, cache bool, err error) {
	if matched := r.matchPolicy(m); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, true, res.Error
	}
	if r.delayedFallback {
		return r.ipExchangeWithDelayedFallback(ctx, m)
	}

	onlyFallback := r.shouldOnlyQueryFallback(m)

	if onlyFallback {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, true, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return msg, true, err
	}

	var fallbackMsg <-chan *result
	if !r.fallbackLazyQuery {
		fallbackMsg = r.asyncExchange(ctx, r.fallback, m)
	}
	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			shouldNotFallback := lo.EveryBy(ips, func(ip netip.Addr) bool {
				return !r.shouldIPFallback(ip)
			})
			if shouldNotFallback {
				msg, err = res.Msg, res.Error // no need to wait for fallback result
				return msg, true, err
			}
		}
	}

	if fallbackMsg == nil {
		fallbackMsg = r.asyncExchange(ctx, r.fallback, m)
	}
	res = <-fallbackMsg
	msg, err = res.Msg, res.Error
	return msg, true, err
}

func (r *Resolver) fallbackQueryTimeout() time.Duration {
	if r.fallbackTimeout > 0 {
		return r.fallbackTimeout
	}
	return resolver.DefaultDNSTimeout
}

func validFallbackResult(query *D.Msg, res *result) bool {
	if res == nil || res.Error != nil || res.Msg == nil || len(query.Question) == 0 {
		return false
	}
	if query.Question[0].Qtype == D.TypeCNAME {
		for _, answer := range res.Msg.Answer {
			if _, ok := answer.(*D.CNAME); ok {
				return true
			}
		}
		return false
	}
	return len(msgToIP(res.Msg)) != 0
}

func fallbackQueryKey(m *D.Msg) string {
	if m == nil || len(m.Question) == 0 {
		return ""
	}
	return strings.ToLower(m.Question[0].String())
}

func (r *Resolver) fallbackState(m *D.Msg, claimRetry bool) (fallbackScope, bool) {
	circuit := r.fallbackCircuit
	if circuit == nil {
		return fallbackScopeNone, false
	}

	now := time.Now()
	key := fallbackQueryKey(m)
	circuit.mu.Lock()
	defer circuit.mu.Unlock()
	if !circuit.groupUntil.IsZero() {
		retry := !now.Before(circuit.groupUntil)
		if retry && claimRetry {
			circuit.groupUntil = now.Add(circuit.interval)
		}
		return fallbackScopeGroup, retry
	}
	if key == "" {
		return fallbackScopeNone, false
	}
	until, found := circuit.domains.Get(key)
	if !found {
		return fallbackScopeNone, false
	}
	retry := !now.Before(until)
	if retry && claimRetry {
		circuit.domains.Set(key, now.Add(circuit.interval))
	}
	return fallbackScopeDomain, retry
}

func (r *Resolver) openDomainFallback(m *D.Msg) bool {
	circuit := r.fallbackCircuit
	key := fallbackQueryKey(m)
	if circuit == nil || key == "" {
		return false
	}

	circuit.mu.Lock()
	_, found := circuit.domains.Get(key)
	if !found {
		circuit.domains.Set(key, time.Now().Add(circuit.interval))
	}
	circuit.mu.Unlock()
	if !found {
		log.Warnln("[DNS] %s query %s is using fallback", r.fallbackLabel, key)
	}
	return !found
}

func (r *Resolver) finishRootProbe(generation uint64, failed bool) {
	circuit := r.fallbackCircuit
	if circuit == nil {
		return
	}

	circuit.mu.Lock()
	if !circuit.probeRunning || circuit.probeGeneration != generation {
		circuit.mu.Unlock()
		return
	}
	circuit.probeRunning = false
	circuit.probeCancel = nil
	opened := false
	if failed {
		opened = circuit.groupUntil.IsZero()
		circuit.groupUntil = time.Now().Add(circuit.interval)
	}
	circuit.mu.Unlock()
	if opened {
		log.Warnln("[DNS] %s primary servers are unavailable, using fallback", r.fallbackLabel)
	}
}

func (r *Resolver) recoverFallback(scope fallbackScope, m *D.Msg) {
	circuit := r.fallbackCircuit
	if circuit == nil {
		return
	}

	key := fallbackQueryKey(m)
	circuit.mu.Lock()
	switch scope {
	case fallbackScopeGroup:
		circuit.groupUntil = time.Time{}
		if key != "" {
			circuit.domains.Delete(key)
		}
	case fallbackScopeDomain:
		circuit.domains.Delete(key)
	}
	probeCancel := circuit.probeCancel
	circuit.probeGeneration++
	circuit.probeRunning = false
	circuit.probeCancel = nil
	circuit.mu.Unlock()
	if probeCancel != nil {
		probeCancel()
	}
	log.Infoln("[DNS] %s primary query recovered for %s", r.fallbackLabel, key)
}

func (r *Resolver) classifyNewFailure(m *D.Msg) {
	circuit := r.fallbackCircuit
	if circuit == nil || !r.openDomainFallback(m) {
		return
	}

	probeCtx, probeCancel := context.WithTimeout(context.Background(), r.fallbackQueryTimeout())
	circuit.mu.Lock()
	if circuit.probeRunning || !circuit.groupUntil.IsZero() {
		circuit.mu.Unlock()
		probeCancel()
		return
	}
	circuit.probeRunning = true
	circuit.probeGeneration++
	generation := circuit.probeGeneration
	circuit.probeCancel = probeCancel
	circuit.mu.Unlock()

	go func() {
		defer probeCancel()
		probe := &D.Msg{}
		probe.SetQuestion(".", D.TypeNS)
		msg, _, err := batchExchange(probeCtx, r.main, probe)
		r.finishRootProbe(generation, err != nil || msg == nil)
	}()
}

func (r *Resolver) exchangeFallbackOnly(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	res := <-r.asyncExchange(ctx, r.fallback, m)
	return res.Msg, res.Error
}

func (r *Resolver) exchangeRecoveryRace(ctx context.Context, m *D.Msg, scope fallbackScope) (*D.Msg, error) {
	mainCtx, cancelMain := context.WithTimeout(context.Background(), r.fallbackQueryTimeout())
	mainCh := r.asyncExchange(mainCtx, r.main, m)
	recoveryCh := make(chan *result, 1)
	go func() {
		res := <-mainCh
		if validFallbackResult(m, res) {
			r.recoverFallback(scope, m)
		}
		cancelMain()
		recoveryCh <- res
	}()

	fallbackCh := r.asyncExchange(ctx, r.fallback, m)
	var mainResult, fallbackResult *result
	for recoveryCh != nil || fallbackCh != nil {
		select {
		case res := <-recoveryCh:
			recoveryCh = nil
			mainResult = res
			if validFallbackResult(m, res) {
				return res.Msg, nil
			}
		case res := <-fallbackCh:
			fallbackCh = nil
			fallbackResult = res
			if validFallbackResult(m, res) {
				return res.Msg, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fallbackResult != nil {
		return fallbackResult.Msg, fallbackResult.Error
	}
	if mainResult != nil {
		return mainResult.Msg, mainResult.Error
	}
	return nil, errors.New("all DNS requests failed")
}

// ipExchangeWithDelayedFallback starts the fallback query after Mihomo's DNS
// timeout, or immediately when all primary servers fail first. Once both tiers
// are running, the first usable response wins.
func (r *Resolver) ipExchangeWithDelayedFallback(ctx context.Context, m *D.Msg) (*D.Msg, bool, error) {
	if scope, retry := r.fallbackState(m, true); scope != fallbackScopeNone {
		if retry {
			msg, err := r.exchangeRecoveryRace(ctx, m, scope)
			return msg, false, err
		}
		msg, err := r.exchangeFallbackOnly(ctx, m)
		return msg, false, err
	}

	mainCh := r.asyncExchange(ctx, r.main, m)
	var fallbackCh <-chan *result
	fallbackStarted := false
	startFallback := func() {
		if !fallbackStarted {
			fallbackStarted = true
			fallbackCh = r.asyncExchange(ctx, r.fallback, m)
		}
	}

	timer := time.NewTimer(r.fallbackQueryTimeout())
	defer timer.Stop()
	timerCh := timer.C

	var mainResult, fallbackResult *result
	failureClassified := false
	cacheable := true
	classifyFailure := func() {
		if !failureClassified {
			failureClassified = true
			cacheable = r.fallbackCircuit == nil
			r.classifyNewFailure(m)
		}
	}
	for mainCh != nil || fallbackCh != nil {
		select {
		case res := <-mainCh:
			mainCh = nil
			mainResult = res
			if validFallbackResult(m, res) {
				return res.Msg, cacheable, nil
			}
			if res == nil || res.Error != nil {
				classifyFailure()
			}
			startFallback()
		case <-timerCh:
			classifyFailure()
			startFallback()
			timerCh = nil
		case res := <-fallbackCh:
			fallbackCh = nil
			fallbackResult = res
			if validFallbackResult(m, res) {
				return res.Msg, cacheable, nil
			}
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}

	if fallbackResult != nil {
		return fallbackResult.Msg, cacheable, fallbackResult.Error
	}
	if mainResult != nil {
		return mainResult.Msg, cacheable, mainResult.Error
	}
	return nil, false, errors.New("all DNS requests failed")
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) (ips []netip.Addr, err error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		ip = ip.Unmap()
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

func (r *Resolver) ClearCache() {
	if r != nil && r.cache != nil {
		r.cache.Clear()
	}
}

func (r *Resolver) ResetConnection() {
	if r != nil {
		for _, c := range r.main {
			c.ResetConnection()
		}
		for _, c := range r.fallback {
			c.ResetConnection()
		}
		if dr := r.defaultResolver; dr != nil {
			dr.ResetConnection()
		}
	}
}

type NameServer struct {
	Net          string
	Addr         string
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
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		maps.Equal(ns.Params, ns2.Params) &&
		ns.PreferH3 == ns2.PreferH3 {
		return true
	}
	return false
}

// transportEqual reports whether two NameServers share the same raw transport and
// may reuse a single client. It compares all fields except wrapper-only params.
func (ns NameServer) transportEqual(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	paramsEqual := func(a, b map[string]string) bool {
		for k, v := range a {
			if isWrapperOnlyParam(k) {
				continue
			}
			if bv, ok := b[k]; !ok || bv != v {
				return false
			}
		}
		return true
	}
	return ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		ns.PreferH3 == ns2.PreferH3 &&
		paramsEqual(ns.Params, ns2.Params) &&
		paramsEqual(ns2.Params, ns.Params)
}

type Policy struct {
	Domain      string
	Matcher     C.DomainMatcher
	NameServers []NameServer
}

type Config struct {
	Main, Fallback       []NameServer
	Default              []NameServer
	ProxyServer          []NameServer
	ProxyFallback        []NameServer
	DirectServer         []NameServer
	DirectFallback       []NameServer
	RecoveryInterval     uint
	DirectFollowPolicy   bool
	IPv6                 bool
	IPv6Timeout          uint
	FallbackIPFilter     []C.IpMatcher
	FallbackDomainFilter []C.DomainMatcher
	FallbackLazyQuery    bool
	Policy               []Policy
	ProxyServerPolicy    []Policy
	CacheAlgorithm       string
	CacheMaxSize         int
}

func (config Config) newCache() dnsCache {
	if config.CacheMaxSize == 0 {
		config.CacheMaxSize = 4096
	}
	switch config.CacheAlgorithm {
	case "arc":
		return arc.New(arc.WithSize[string, *D.Msg](config.CacheMaxSize))
	default:
		return lru.New(lru.WithSize[string, *D.Msg](config.CacheMaxSize), lru.WithStale[string, *D.Msg](true))
	}
}

type Resolvers struct {
	*Resolver
	ProxyResolver  *Resolver
	DirectResolver *Resolver
}

func (rs Resolvers) ClearCache() {
	rs.Resolver.ClearCache()
	rs.ProxyResolver.ClearCache()
	rs.DirectResolver.ClearCache()
}

func (rs Resolvers) ResetConnection() {
	rs.Resolver.ResetConnection()
	rs.ProxyResolver.ResetConnection()
	rs.DirectResolver.ResetConnection()
}

func NewResolverFromClient(client dnsClient) *Resolver {
	return &Resolver{
		ipv6:  true,
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}
}

func NewResolver(config Config) (rs Resolvers) {
	makeFallbackCircuit := func() *fallbackCircuit {
		return newFallbackCircuit(time.Duration(config.RecoveryInterval) * time.Millisecond)
	}

	defaultResolver := &Resolver{
		main:        transform(config.Default, nil),
		cache:       config.newCache(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
	}

	var nameServerCache []struct {
		NameServer
		dnsClient
	}
	cacheTransform := func(nameserver []NameServer) (result []dnsClient) {
	LOOP:
		for _, ns := range nameserver {
			var dc dnsClient
			for _, nsc := range nameServerCache {
				if nsc.NameServer.Equal(ns) {
					result = append(result, nsc.dnsClient)
					continue LOOP // exact match wins: reuse the wrapped client as-is
				}
				if dc == nil && nsc.NameServer.transportEqual(ns) {
					dc = nsc.dnsClient // reusable raw transport; keep scanning for an exact match
				}
			}
			if dc != nil { // reuse raw transport, re-wrap the client
				dc = rewrapClient(dc, ns.Params)
			} else { // no reusable transport: build from scratch
				built := transform([]NameServer{ns}, defaultResolver)
				if len(built) == 0 {
					continue
				}
				dc = built[0]
			}
			nameServerCache = append(nameServerCache, struct {
				NameServer
				dnsClient
			}{NameServer: ns, dnsClient: dc})
			result = append(result, dc)
		}
		return
	}

	makePolicy := func(policies []Policy) (dnsPolicies []dnsPolicy) {
		var triePolicy *trie.DomainTrie[[]dnsClient]
		insertPolicy := func(policy dnsPolicy) {
			if triePolicy != nil {
				triePolicy.Optimize()
				dnsPolicies = append(dnsPolicies, domainTriePolicy{triePolicy})
				triePolicy = nil
			}
			if policy != nil {
				dnsPolicies = append(dnsPolicies, policy)
			}
		}

		for _, policy := range policies {
			if policy.Matcher != nil {
				insertPolicy(domainMatcherPolicy{matcher: policy.Matcher, dnsClients: cacheTransform(policy.NameServers)})
			} else {
				if triePolicy == nil {
					triePolicy = trie.New[[]dnsClient]()
				}
				if err := triePolicy.Insert(policy.Domain, cacheTransform(policy.NameServers)); err != nil {
					log.Warnln("[DNS] skip invalid nameserver policy: %s", err)
				}
			}
		}
		insertPolicy(nil)
		return
	}

	r := &Resolver{
		ipv6:        config.IPv6,
		main:        cacheTransform(config.Main),
		cache:       config.newCache(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
		policy:      makePolicy(config.Policy),
	}
	r.defaultResolver = defaultResolver
	rs.Resolver = r

	if len(config.ProxyServer) != 0 {
		rs.ProxyResolver = &Resolver{
			ipv6:            config.IPv6,
			main:            cacheTransform(config.ProxyServer),
			fallback:        cacheTransform(config.ProxyFallback),
			delayedFallback: len(config.ProxyFallback) != 0,
			fallbackLabel:   "proxy-server-nameserver",
			cache:           config.newCache(),
			ipv6Timeout:     time.Duration(config.IPv6Timeout) * time.Millisecond,
			policy:          makePolicy(config.ProxyServerPolicy),
		}
		if rs.ProxyResolver.delayedFallback {
			rs.ProxyResolver.fallbackCircuit = makeFallbackCircuit()
		}
	}

	if len(config.DirectServer) != 0 {
		rs.DirectResolver = &Resolver{
			ipv6:            config.IPv6,
			main:            cacheTransform(config.DirectServer),
			fallback:        cacheTransform(config.DirectFallback),
			delayedFallback: len(config.DirectFallback) != 0,
			fallbackLabel:   "direct-nameserver",
			cache:           config.newCache(),
			ipv6Timeout:     time.Duration(config.IPv6Timeout) * time.Millisecond,
		}
		if rs.DirectResolver.delayedFallback {
			rs.DirectResolver.fallbackCircuit = makeFallbackCircuit()
		}
		if config.DirectFollowPolicy {
			rs.DirectResolver.policy = r.policy
		}
	}

	if len(config.Fallback) != 0 {
		r.fallback = cacheTransform(config.Fallback)
		r.fallbackIPFilters = config.FallbackIPFilter
		r.fallbackDomainFilters = config.FallbackDomainFilter
		r.fallbackLazyQuery = config.FallbackLazyQuery
	}

	return
}

var ParseNameServer func(servers []string) ([]NameServer, error) // define in config/config.go
