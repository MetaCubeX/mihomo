package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"golang.org/x/net/publicsuffix"
)

type LoadBalanceOption struct {
	Strategy string `group:"strategy,omitempty"`
	HashKey  string `group:"hash-key,omitempty"`
}

type LoadBalance struct {
	*GroupBase
	disableUDP     bool
	strategyFn     strategyFn
	leastConn      *leastConnections // set only for strategy least-connections
	testUrl        string
	expectedStatus string
}

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy

var errStrategy = errors.New("unsupported strategy")
var errHashKey = errors.New("unsupported hash-key")

// keyFn derives the value a hashing strategy pins a request on.
type keyFn = func(metadata *C.Metadata) string

func getKey(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}

	if metadata.Host != "" {
		// ip host
		if ip := net.ParseIP(metadata.Host); ip != nil {
			return metadata.Host
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadata.Host); err == nil {
			return etld
		}
	}

	if !metadata.DstIP.IsValid() {
		return ""
	}

	return metadata.DstIP.String()
}

func getKeyWithSrcAndDst(metadata *C.Metadata) string {
	dst := getKey(metadata)
	src := ""
	if metadata != nil {
		src = metadata.SrcIP.String()
	}

	return fmt.Sprintf("%s%s", src, dst)
}

// getKeyWithInUser pins on the authenticated inbound user instead of on an
// address. Both address-derived keys assume one client's traffic to one
// destination is one unit of work, which is false for a client whose single
// unit of work walks several destinations: the hash moves with the host, and
// the egress IP changes underneath a session the destination is tracking.
// The inbound user is the only identity the client itself controls, and
// `IN-USER` rules already match on it -- hence the option value `in-user`,
// which names the same thing those rules do. An unauthenticated request keeps
// the strategy's own key rather than collapsing every such request onto one
// node.
func getKeyWithInUser(fallback keyFn) keyFn {
	return func(metadata *C.Metadata) string {
		if metadata != nil && metadata.InUser != "" {
			return metadata.InUser
		}

		return fallback(metadata)
	}
}

// hashKey resolves the `hash-key` option into a decorator over whichever key
// the chosen strategy derives by default.
func hashKey(name string) (func(keyFn) keyFn, error) {
	switch name {
	case "":
		return func(fn keyFn) keyFn { return fn }, nil
	case "in-user":
		return getKeyWithInUser, nil
	}

	return nil, fmt.Errorf("%w: %s", errHashKey, name)
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

// pick chooses the member for a new connection. The returned release must be
// called once that connection is gone (or never came up); it is a no-op for
// every strategy but least-connections.
func (lb *LoadBalance) pick(metadata *C.Metadata) (C.Proxy, func()) {
	if lb.leastConn != nil {
		return lb.leastConn.pick(lb.GetProxies(true), lb.testUrl, true)
	}
	return lb.Unwrap(metadata, true), func() {}
}

// DialContext implements C.ProxyAdapter
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy, release := lb.pick(metadata)
	c, err = proxy.DialContext(ctx, metadata)

	if err == nil {
		c.AppendToChains(lb)
	} else {
		release()
		lb.onDialFailed(proxy.Type(), err, lb.healthCheck)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				lb.onDialSuccess()
			} else {
				lb.onDialFailed(proxy.Type(), err, lb.healthCheck)
			}
		})
	}

	if err == nil && lb.leastConn != nil {
		c = callback.NewCloseCallbackConn(c, release)
	}

	return
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy, release := lb.pick(metadata)
	pc, err = proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		release()
		return
	}
	if lb.leastConn != nil {
		pc = callback.NewCloseCallbackPacketConn(pc, release)
	}
	return
}

// SupportUDP implements C.ProxyAdapter
func (lb *LoadBalance) SupportUDP() bool {
	return !lb.disableUDP
}

// IsL3Protocol implements C.ProxyAdapter
func (lb *LoadBalance) IsL3Protocol(metadata *C.Metadata) bool {
	return lb.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func strategyRoundRobin(url string) strategyFn {
	idx := 0
	idxMutex := sync.Mutex{}
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		idxMutex.Lock()
		defer idxMutex.Unlock()

		i := 0
		length := len(proxies)

		if touch {
			defer func() {
				idx = (idx + i) % length
			}()
		}

		for ; i < length; i++ {
			id := (idx + i) % length
			proxy := proxies[id]
			if proxy.AliveForTestUrl(url) {
				i++
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyConsistentHashing(url string, keyOf keyFn) strategyFn {
	maxRetry := 5
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(keyOf(metadata))
		buckets := int32(len(proxies))
		for i := 0; i < maxRetry; i, key = i+1, key+1 {
			idx := jumpHash(key, buckets)
			proxy := proxies[idx]
			if proxy.AliveForTestUrl(url) {
				return proxy
			}
		}

		// when availability is poor, traverse the entire list to get the available nodes
		for _, proxy := range proxies {
			if proxy.AliveForTestUrl(url) {
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyStickySessions(url string, keyOf keyFn) strategyFn {
	ttl := time.Minute * 10
	maxRetry := 5
	lruCache := lru.New[uint64, int](
		lru.WithAge[uint64, int](int64(ttl.Seconds())),
		lru.WithSize[uint64, int](1000))
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(keyOf(metadata))
		length := len(proxies)
		idx, has := lruCache.Get(key)
		if !has || idx >= length {
			idx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
		}

		nowIdx := idx
		for i := 1; i < maxRetry; i++ {
			proxy := proxies[nowIdx]
			if proxy.AliveForTestUrl(url) {
				if !has || nowIdx != idx {
					lruCache.Set(key, nowIdx)
				}

				return proxy
			} else {
				nowIdx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
			}
		}

		lruCache.Set(key, 0)
		return proxies[0]
	}
}

// leastConnections hands each new connection to the alive member with the
// fewest open connections per share. A member listed N times in the group
// holds N shares, as it already gets N turns under round-robin; this is how a
// faster link is given a larger part of the traffic. Unlike the hashing
// strategies it spreads the connections of one destination too, which is what
// a download split over parallel connections needs, at the cost of any
// affinity: a destination that ties a session to the egress IP belongs in a
// sticky group instead.
//
// A connection is counted from the moment its member is picked, not from when
// the dial completes, so a burst of simultaneous requests spreads instead of
// piling onto whichever member looked idlest.
type leastConnections struct {
	mu     sync.Mutex
	active map[C.Proxy]int
	next   int // rotates where the scan starts, so ties do not all go to the first member
}

func newLeastConnections() *leastConnections {
	return &leastConnections{active: map[C.Proxy]int{}}
}

// pick returns the chosen member and, when acquire is set, counts a
// connection on it; the returned release undoes that count and is safe to
// call more than once.
func (lc *leastConnections) pick(proxies []C.Proxy, url string, acquire bool) (C.Proxy, func()) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	shares := make(map[C.Proxy]int, len(proxies))
	for _, proxy := range proxies {
		shares[proxy]++
	}

	length := len(proxies)
	var best C.Proxy
	bestActive, bestShares := 0, 0
	for i := 0; i < length; i++ {
		proxy := proxies[(lc.next+i)%length]
		if !proxy.AliveForTestUrl(url) {
			continue
		}
		// (active+1)/shares < (bestActive+1)/bestShares, kept in integers.
		active, n := lc.active[proxy], shares[proxy]
		if best == nil || (active+1)*bestShares < (bestActive+1)*n {
			best, bestActive, bestShares = proxy, active, n
		}
	}
	if best == nil {
		best = proxies[0]
	}

	if !acquire {
		return best, func() {}
	}

	lc.next = (lc.next + 1) % length
	lc.active[best]++
	var once sync.Once
	return best, func() {
		once.Do(func() {
			lc.mu.Lock()
			defer lc.mu.Unlock()
			if lc.active[best]--; lc.active[best] <= 0 {
				delete(lc.active, best)
			}
		})
	}
}

// Unwrap implements C.ProxyAdapter
func (lb *LoadBalance) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := lb.GetProxies(touch)
	return lb.strategyFn(proxies, metadata, touch)
}

// MarshalJSON implements C.ProxyAdapter
func (lb *LoadBalance) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           lb.Type().String(),
		"all":            all,
		"testUrl":        lb.testUrl,
		"expectedStatus": lb.expectedStatus,
		"hidden":         lb.Hidden(),
		"icon":           lb.Icon(),
		"emptyFallback":  lb.EmptyFallback().Name(),
	})
}

func (lb *LoadBalance) Providers() []P.ProxyProvider {
	return lb.providers
}

func (lb *LoadBalance) Proxies() []C.Proxy {
	return lb.GetProxies(false)
}

func (lb *LoadBalance) Now() string {
	return ""
}

func NewLoadBalance(option GroupCommonOption, loadBalanceOption LoadBalanceOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (lb *LoadBalance, err error) {
	var strategyFn strategyFn
	var leastConn *leastConnections
	withKey, err := hashKey(loadBalanceOption.HashKey)
	if err != nil {
		return nil, err
	}
	switch loadBalanceOption.Strategy {
	case "", "consistent-hashing":
		strategyFn = strategyConsistentHashing(option.URL, withKey(getKey))
	case "round-robin":
		// Rejected rather than ignored: round-robin hashes nothing, so a
		// hash-key here means the config expects stickiness it will not get.
		if loadBalanceOption.HashKey != "" {
			return nil, fmt.Errorf("%w: round-robin does not hash", errHashKey)
		}
		strategyFn = strategyRoundRobin(option.URL)
	case "sticky-sessions":
		strategyFn = strategyStickySessions(option.URL, withKey(getKeyWithSrcAndDst))
	case "least-connections":
		// Rejected for the same reason as round-robin: it hashes nothing.
		if loadBalanceOption.HashKey != "" {
			return nil, fmt.Errorf("%w: least-connections does not hash", errHashKey)
		}
		leastConn = newLeastConnections()
		// Unwrap only reports the member a connection would get; dials count
		// through lb.pick instead.
		strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
			proxy, _ := leastConn.pick(proxies, option.URL, false)
			return proxy
		}
	default:
		return nil, fmt.Errorf("%w: %s", errStrategy, loadBalanceOption.Strategy)
	}
	return &LoadBalance{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.LoadBalance,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			EmptyFallback:  emptyFallback,
			Providers:      providers,
		}),
		strategyFn:     strategyFn,
		leastConn:      leastConn,
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
	}, nil
}
