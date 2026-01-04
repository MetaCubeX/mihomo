package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type Smart struct {
	*GroupBase
	disableUDP     bool
	testUrl        string
	expectedStatus string
	Hidden         bool
	Icon           string

	mu              sync.RWMutex
	proxyStats      map[string]*proxyStats
	selectedProxy   C.Proxy
	healthCheckTime time.Time
}

type proxyStats struct {
	totalRequests   uint64
	successRequests uint64
	failedRequests  uint64
	totalDelay      uint64
	lastSuccessTime time.Time
	lastFailureTime time.Time
	mu              sync.RWMutex
}

type smartOption func(*Smart)

func smartWithDisableUDP() smartOption {
	return func(s *Smart) {
		s.disableUDP = true
	}
}

func (s *Smart) Now() string {
	s.mu.RLock()
	if s.selectedProxy != nil {
		name := s.selectedProxy.Name()
		s.mu.RUnlock()
		return name
	}
	s.mu.RUnlock()

	proxy := s.selectBestProxy(false)
	if proxy != nil {
		return proxy.Name()
	}
	return ""
}

func (s *Smart) Set(name string) error {
	proxies := s.GetProxies(false)
	for _, proxy := range proxies {
		if proxy.Name() == name {
			s.mu.Lock()
			s.selectedProxy = proxy
			s.mu.Unlock()
			return nil
		}
	}
	return errors.New("proxy not exist")
}

func (s *Smart) ForceSet(name string) {
	proxies := s.GetProxies(false)
	for _, proxy := range proxies {
		if proxy.Name() == name {
			s.mu.Lock()
			s.selectedProxy = proxy
			s.mu.Unlock()
			break
		}
	}
}

func (s *Smart) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	startTime := time.Now()
	proxy := s.selectBestProxy(true)
	c, err = proxy.DialContext(ctx, metadata)
	delay := uint64(time.Since(startTime).Milliseconds())

	if err == nil {
		c.AppendToChains(s)
		s.recordSuccess(proxy.Name(), delay)
	} else {
		s.recordFailure(proxy.Name())
		s.onDialFailed(proxy.Type(), err, s.healthCheck)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				s.recordSuccess(proxy.Name(), 0)
			} else {
				s.recordFailure(proxy.Name())
			}
		})
	}

	return c, err
}

func (s *Smart) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	proxy := s.selectBestProxy(true)
	pc, err = proxy.ListenPacketContext(ctx, metadata)

	if err == nil {
		pc.AppendToChains(s)
	} else {
		s.recordFailure(proxy.Name())
		s.onDialFailed(proxy.Type(), err, s.healthCheck)
	}

	return pc, err
}

func (s *Smart) SupportUDP() bool {
	if s.disableUDP {
		return false
	}
	return s.selectBestProxy(false).SupportUDP()
}

func (s *Smart) IsL3Protocol(metadata *C.Metadata) bool {
	return s.selectBestProxy(false).IsL3Protocol(metadata)
}

func (s *Smart) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return s.selectBestProxy(touch)
}

func (s *Smart) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range s.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           s.Type().String(),
		"now":            s.Now(),
		"all":            all,
		"testUrl":        s.testUrl,
		"expectedStatus": s.expectedStatus,
		"hidden":         s.Hidden,
		"icon":           s.Icon,
	})
}

func (s *Smart) Providers() []P.ProxyProvider {
	return s.providers
}

func (s *Smart) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

func (s *Smart) selectBestProxy(touch bool) C.Proxy {
	s.mu.Lock()
	defer s.mu.Unlock()

	proxies := s.GetProxies(touch)
	if len(proxies) == 0 {
		return nil
	}

	now := time.Now()

	if s.selectedProxy != nil {
		stats := s.getProxyStatsLocked(s.selectedProxy.Name())
		if stats != nil && stats.isHealthy(now) {
			if stats.totalRequests > 0 && stats.totalRequests%100 == 0 {
				bestProxy := proxies[0]
				bestScore := s.calculateProxyScoreLocked(bestProxy, now)

				for _, proxy := range proxies[1:] {
					if !proxy.AliveForTestUrl(s.testUrl) {
						continue
					}

					score := s.calculateProxyScoreLocked(proxy, now)
					if score > bestScore {
						bestProxy = proxy
						bestScore = score
					}
				}

				if bestProxy.Name() != s.selectedProxy.Name() && bestScore > s.calculateProxyScoreLocked(s.selectedProxy, now)+5 {
					s.selectedProxy = bestProxy
					return bestProxy
				}
			}
			return s.selectedProxy
		}
	}

	bestProxy := proxies[0]
	bestScore := s.calculateProxyScoreLocked(bestProxy, now)

	for _, proxy := range proxies[1:] {
		if !proxy.AliveForTestUrl(s.testUrl) {
			continue
		}

		score := s.calculateProxyScoreLocked(proxy, now)
		if score > bestScore {
			bestProxy = proxy
			bestScore = score
		}
	}

	s.selectedProxy = bestProxy
	return bestProxy
}

func (s *Smart) calculateProxyScore(proxy C.Proxy, now time.Time) float64 {
	stats := s.getProxyStats(proxy.Name())
	if stats == nil {
		return 0
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.totalRequests == 0 {
		return 50
	}

	successRate := float64(stats.successRequests) / float64(stats.totalRequests)

	avgDelay := float64(stats.totalDelay) / float64(stats.successRequests)
	if avgDelay == 0 {
		avgDelay = float64(proxy.LastDelayForTestUrl(s.testUrl))
		if avgDelay == 0 {
			avgDelay = 100
		}
	}

	delayScore := math.Max(0, 100-avgDelay/10)
	successScore := successRate * 100

	timeSinceLastFailure := now.Sub(stats.lastFailureTime).Minutes()
	stabilityBonus := math.Min(10, timeSinceLastFailure/5)

	score := (successScore * 0.6) + (delayScore * 0.3) + stabilityBonus

	return score
}

func (s *Smart) getProxyStats(name string) *proxyStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proxyStats[name]
}

func (s *Smart) getProxyStatsLocked(name string) *proxyStats {
	return s.proxyStats[name]
}

func (s *Smart) calculateProxyScoreLocked(proxy C.Proxy, now time.Time) float64 {
	stats := s.getProxyStatsLocked(proxy.Name())
	if stats == nil {
		delay := float64(proxy.LastDelayForTestUrl(s.testUrl))
		if delay == 0 {
			delay = 100
		}
		delayScore := math.Max(0, 100-delay/10)
		return delayScore
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.totalRequests == 0 {
		delay := float64(proxy.LastDelayForTestUrl(s.testUrl))
		if delay == 0 {
			delay = 100
		}
		delayScore := math.Max(0, 100-delay/10)
		return delayScore
	}

	successRate := float64(stats.successRequests) / float64(stats.totalRequests)

	avgDelay := float64(stats.totalDelay) / float64(stats.successRequests)
	if avgDelay == 0 {
		avgDelay = float64(proxy.LastDelayForTestUrl(s.testUrl))
		if avgDelay == 0 {
			avgDelay = 100
		}
	}

	delayScore := math.Max(0, 100-avgDelay/10)
	successScore := successRate * 100

	timeSinceLastFailure := now.Sub(stats.lastFailureTime).Minutes()
	stabilityBonus := math.Min(10, timeSinceLastFailure/5)

	score := (successScore * 0.6) + (delayScore * 0.3) + stabilityBonus

	return score
}

func (s *Smart) recordSuccess(proxyName string, delay uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := s.proxyStats[proxyName]
	if stats == nil {
		stats = &proxyStats{}
		s.proxyStats[proxyName] = stats
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.totalRequests++
	stats.successRequests++
	stats.totalDelay += delay
	stats.lastSuccessTime = time.Now()
}

func (s *Smart) recordFailure(proxyName string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := s.proxyStats[proxyName]
	if stats == nil {
		stats = &proxyStats{}
		s.proxyStats[proxyName] = stats
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.totalRequests++
	stats.failedRequests++
	stats.lastFailureTime = time.Now()

	if stats.failedRequests >= 5 {
		s.selectedProxy = nil
	}
}

func (ps *proxyStats) isHealthy(now time.Time) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.totalRequests < 10 {
		return true
	}

	successRate := float64(ps.successRequests) / float64(ps.totalRequests)
	if successRate < 0.7 {
		return false
	}

	timeSinceLastFailure := now.Sub(ps.lastFailureTime).Minutes()
	if timeSinceLastFailure < 1 && ps.failedRequests >= 3 {
		return false
	}

	return true
}

func (s *Smart) healthCheck() {
	s.mu.Lock()
	s.healthCheckTime = time.Now()
	s.mu.Unlock()

	s.GroupBase.healthCheck()

	proxies := s.GetProxies(false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	expectedStatus, _ := utils.NewUnsignedRanges[uint16](s.expectedStatus)

	for _, proxy := range proxies {
		go func(p C.Proxy) {
			delay, err := p.URLTest(ctx, s.testUrl, expectedStatus)
			if err == nil {
				stats := s.getProxyStats(p.Name())
				if stats != nil {
					stats.mu.Lock()
					stats.totalDelay += uint64(delay)
					stats.mu.Unlock()
				}
			}
		}(proxy)
	}
}

func NewSmart(option *GroupCommonOption, providers []P.ProxyProvider, options ...smartOption) *Smart {
	smart := &Smart{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Smart,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			Providers:      providers,
		}),
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		Hidden:         option.Hidden,
		Icon:           option.Icon,
		proxyStats:     make(map[string]*proxyStats),
	}

	for _, opt := range options {
		opt(smart)
	}

	return smart
}
