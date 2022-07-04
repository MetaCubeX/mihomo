package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/common/cache"
	"net"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/murmur3"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"

	"golang.org/x/net/publicsuffix"
)

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata) C.Proxy

type LoadBalance struct {
	*GroupBase
	disableUDP bool
	strategyFn strategyFn
}

var errStrategy = errors.New("unsupported strategy")

func parseStrategy(config map[string]any) string {
	if strategy, ok := config["strategy"].(string); ok {
		return strategy
	}
	return "consistent-hashing"
}

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
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (c C.Conn, err error) {
	defer func() {
		if err == nil {
			c.AppendToChains(lb)
			lb.onDialSuccess()
		} else {
			lb.onDialFailed()
		}
	}()

	proxy := lb.Unwrap(metadata)

	c, err = proxy.DialContext(ctx, metadata, lb.Base.DialOptions(opts...)...)
	return
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata)
	return proxy.ListenPacketContext(ctx, metadata, lb.Base.DialOptions(opts...)...)
}

// SupportUDP implements C.ProxyAdapter
func (lb *LoadBalance) SupportUDP() bool {
	return !lb.disableUDP
}

func strategyRoundRobin() strategyFn {
	idx := 0
	return func(proxies []C.Proxy, metadata *C.Metadata) C.Proxy {
		length := len(proxies)
		for i := 0; i < length; i++ {
			idx = (idx + 1) % length
			proxy := proxies[idx]
			if proxy.Alive() {
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyConsistentHashing() strategyFn {
	maxRetry := 5
	return func(proxies []C.Proxy, metadata *C.Metadata) C.Proxy {
		key := uint64(murmur3.Sum32([]byte(getKey(metadata))))
		buckets := int32(len(proxies))
		for i := 0; i < maxRetry; i, key = i+1, key+1 {
			idx := jumpHash(key, buckets)
			proxy := proxies[idx]
			if proxy.Alive() {
				return proxy
			}
		}

		// when availability is poor, traverse the entire list to get the available nodes
		for _, proxy := range proxies {
			if proxy.Alive() {
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyStickySessions() strategyFn {
	ttl := time.Minute * 10
	maxRetry := 5
	lruCache := cache.NewLRUCache[uint64, int](
		cache.WithAge[uint64, int](int64(ttl.Seconds())),
		cache.WithSize[uint64, int](1000))
	return func(proxies []C.Proxy, metadata *C.Metadata) C.Proxy {
		key := uint64(murmur3.Sum32([]byte(getKeyWithSrcAndDst(metadata))))
		length := len(proxies)
		idx, has := lruCache.Get(key)
		if !has {
			idx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
		}

		nowIdx := idx
		for i := 1; i < maxRetry; i++ {
			proxy := proxies[nowIdx]
			if proxy.Alive() {
				if nowIdx != idx {
					lruCache.Delete(key)
					lruCache.Set(key, nowIdx)
				}

				return proxy
			} else {
				nowIdx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
			}
		}

		lruCache.Delete(key)
		lruCache.Set(key, 0)
		return proxies[0]
	}
}

// Unwrap implements C.ProxyAdapter
func (lb *LoadBalance) Unwrap(metadata *C.Metadata) C.Proxy {
	proxies := lb.GetProxies(true)
	return lb.strategyFn(proxies, metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (lb *LoadBalance) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": lb.Type().String(),
		"all":  all,
	})
}

func NewLoadBalance(option *GroupCommonOption, providers []provider.ProxyProvider, strategy string) (lb *LoadBalance, err error) {
	var strategyFn strategyFn
	switch strategy {
	case "consistent-hashing":
		strategyFn = strategyConsistentHashing()
	case "round-robin":
		strategyFn = strategyRoundRobin()
	case "sticky-sessions":
		strategyFn = strategyStickySessions()
	default:
		return nil, fmt.Errorf("%w: %s", errStrategy, strategy)
	}
	return &LoadBalance{
		GroupBase: NewGroupBase(GroupBaseOption{
			outbound.BaseOption{
				Name:        option.Name,
				Type:        C.LoadBalance,
				Interface:   option.Interface,
				RoutingMark: option.RoutingMark,
			},
			option.Filter,
			providers,
		}),
		strategyFn: strategyFn,
		disableUDP: option.DisableUDP,
	}, nil
}
