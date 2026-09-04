package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
	Strategy  string `group:"strategy,omitempty"`
	Weighting string `group:"weighting,omitempty"`
	TopN      int    `group:"top-n,omitempty"`
}

type LoadBalance struct {
	*GroupBase
	disableUDP     bool
	strategyFn     strategyFn
	testUrl        string
	expectedStatus string
	weighting      string
	topN           int
}

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy

var errStrategy = errors.New("unsupported strategy")

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

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

// DialContext implements C.ProxyAdapter
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy := lb.Unwrap(metadata, true)
	c, err = proxy.DialContext(ctx, metadata)

	if err == nil {
		c.AppendToChains(lb)
	} else {
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

	return
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata, true)
	return proxy.ListenPacketContext(ctx, metadata)
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

func strategyConsistentHashing(url string) strategyFn {
	maxRetry := 5
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKey(metadata))
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

func strategyStickySessions(url string) strategyFn {
	ttl := time.Minute * 10
	maxRetry := 5
	lruCache := lru.New[uint64, int](
		lru.WithAge[uint64, int](int64(ttl.Seconds())),
		lru.WithSize[uint64, int](1000))
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKeyWithSrcAndDst(metadata))
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

type latencyCandidate struct {
	proxy C.Proxy
	name  string
	delay uint16
}

func insertTopLatencyCandidate(candidates []latencyCandidate, candidate latencyCandidate, topN int) []latencyCandidate {
	if topN <= 0 {
		return append(candidates, candidate)
	}

	insertAt := len(candidates)
	for i, current := range candidates {
		if candidate.delay < current.delay || candidate.delay == current.delay && candidate.name < current.name {
			insertAt = i
			break
		}
	}

	if insertAt >= topN {
		return candidates
	}

	candidates = append(candidates, latencyCandidate{})
	copy(candidates[insertAt+1:], candidates[insertAt:])
	candidates[insertAt] = candidate
	if len(candidates) > topN {
		candidates = candidates[:topN]
	}
	return candidates
}

func weightedCandidateScore(key uint64, candidate latencyCandidate) float64 {
	hash := key ^ utils.MapHash(candidate.name)
	// SplitMix64 finalizer avoids correlations between the session and proxy hashes.
	hash ^= hash >> 30
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 27
	hash *= 0x94d049bb133111eb
	hash ^= hash >> 31

	// Weighted rendezvous hashing: inverse latency is the weight, so the
	// equivalent exponential-race score is -log(U) * latency. Lowest wins.
	uniform := (float64(hash>>11) + 1) / (1 << 53)
	return -math.Log(uniform) * float64(candidate.delay)
}

func selectLatencyWeightedCandidate(candidates []latencyCandidate, key uint64) latencyCandidate {
	selected := candidates[0]
	minScore := weightedCandidateScore(key, selected)
	for _, candidate := range candidates[1:] {
		score := weightedCandidateScore(key, candidate)
		if score < minScore {
			selected = candidate
			minScore = score
		}
	}
	return selected
}

func strategyStickySessionsLatencyWeighted(url string, topN int) strategyFn {
	ttl := time.Minute * 10
	stickyCache := lru.New[uint64, string](
		lru.WithAge[uint64, string](int64(ttl.Seconds())),
		lru.WithSize[uint64, string](1000))

	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKeyWithSrcAndDst(metadata))
		if cachedName, has := stickyCache.Get(key); has {
			for _, proxy := range proxies {
				if proxy.Name() == cachedName && proxy.AliveForTestUrl(url) {
					return proxy
				}
			}
		}

		var candidates []latencyCandidate
		alive := make([]C.Proxy, 0, len(proxies))
		if topN > 0 {
			capacity := topN
			if capacity > len(proxies) {
				capacity = len(proxies)
			}
			candidates = make([]latencyCandidate, 0, capacity)
		} else {
			candidates = make([]latencyCandidate, 0, len(proxies))
		}

		for _, proxy := range proxies {
			if !proxy.AliveForTestUrl(url) {
				continue
			}
			alive = append(alive, proxy)
			delay := proxy.LastDelayForTestUrl(url)
			if delay == math.MaxUint16 {
				continue
			}
			candidates = insertTopLatencyCandidate(candidates, latencyCandidate{
				proxy: proxy,
				name:  proxy.Name(),
				delay: delay,
			}, topN)
		}

		var selected C.Proxy
		if len(candidates) > 0 {
			selected = selectLatencyWeightedCandidate(candidates, key).proxy
		} else if len(alive) > 0 {
			// Until the first health-check result is available, retain usable
			// sticky behavior without treating unknown latency as the fastest.
			selected = alive[int(jumpHash(key, int32(len(alive))))]
		} else {
			selected = proxies[0]
		}

		stickyCache.Set(key, selected.Name())
		return selected
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
		"weighting":      lb.weighting,
		"topN":           lb.topN,
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
	if loadBalanceOption.TopN < 0 {
		return nil, errors.New("top-n must not be negative")
	}
	if loadBalanceOption.TopN > 0 && loadBalanceOption.Weighting == "" {
		return nil, errors.New("top-n requires weighting")
	}
	if loadBalanceOption.Weighting != "" && loadBalanceOption.Strategy != "sticky-sessions" {
		return nil, errors.New("weighting is only supported by sticky-sessions")
	}

	var strategyFn strategyFn
	switch loadBalanceOption.Strategy {
	case "", "consistent-hashing":
		strategyFn = strategyConsistentHashing(option.URL)
	case "round-robin":
		strategyFn = strategyRoundRobin(option.URL)
	case "sticky-sessions":
		switch loadBalanceOption.Weighting {
		case "":
			strategyFn = strategyStickySessions(option.URL)
		case "inverse-latency":
			strategyFn = strategyStickySessionsLatencyWeighted(option.URL, loadBalanceOption.TopN)
		default:
			return nil, fmt.Errorf("unsupported weighting: %s", loadBalanceOption.Weighting)
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
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		weighting:      loadBalanceOption.Weighting,
		topN:           loadBalanceOption.TopN,
	}, nil
}
