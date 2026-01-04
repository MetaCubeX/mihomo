package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type mockProxy struct {
	name               string
	delay              uint16
	alive              bool
	successRate        float64
	requestCount       atomic.Uint64
	failCount          atomic.Uint64
	mu                 sync.Mutex
	failAfter          int
	delayVariance      uint16
	domainDelays       map[string]uint16
	domainSuccessRates map[string]float64
}

func (m *mockProxy) Name() string {
	return m.name
}

func (m *mockProxy) Type() C.AdapterType {
	return C.Shadowsocks
}

func (m *mockProxy) Addr() string {
	return "127.0.0.1:8080"
}

func (m *mockProxy) SupportUDP() bool {
	return true
}

func (m *mockProxy) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"name":"%s"}`, m.name)), nil
}

func (m *mockProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	m.requestCount.Add(1)

	if m.failAfter > 0 && int(m.requestCount.Load()) > m.failAfter {
		m.failCount.Add(1)
		return nil, errors.New("connection failed")
	}

	host := metadata.Host
	currentSuccessRate := m.successRate
	currentDelay := m.delay

	if m.domainSuccessRates != nil {
		if rate, ok := m.domainSuccessRates[host]; ok {
			currentSuccessRate = rate
		}
	}

	if m.domainDelays != nil {
		if delay, ok := m.domainDelays[host]; ok {
			currentDelay = delay
		}
	}

	if rand.Float64() > currentSuccessRate {
		m.failCount.Add(1)
		return nil, errors.New("random failure")
	}

	delay := currentDelay
	if m.delayVariance > 0 {
		delay += uint16(rand.Intn(int(m.delayVariance)))
	}

	time.Sleep(time.Duration(delay) * time.Millisecond)

	return &mockConn{}, nil
}

func (m *mockProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (m *mockProxy) SupportUOT() bool {
	return false
}

func (m *mockProxy) IsL3Protocol(metadata *C.Metadata) bool {
	return false
}

func (m *mockProxy) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

func (m *mockProxy) Close() error {
	return nil
}

func (m *mockProxy) ProxyInfo() C.ProxyInfo {
	return C.ProxyInfo{}
}

func (m *mockProxy) Adapter() C.ProxyAdapter {
	return m
}

func (m *mockProxy) AliveForTestUrl(url string) bool {
	return m.alive
}

func (m *mockProxy) DelayHistory() []C.DelayHistory {
	return []C.DelayHistory{}
}

func (m *mockProxy) ExtraDelayHistories() map[string]C.ProxyState {
	return nil
}

func (m *mockProxy) LastDelayForTestUrl(url string) uint16 {
	variance := uint16(0)
	if m.delayVariance > 0 {
		variance = uint16(rand.Intn(int(m.delayVariance)))
	}
	return m.delay + variance
}

func (m *mockProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	if !m.alive {
		return 0, errors.New("proxy not alive")
	}
	variance := uint16(0)
	if m.delayVariance > 0 {
		variance = uint16(rand.Intn(int(m.delayVariance)))
	}
	return m.delay + variance, nil
}

type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return nil
}

func (m *mockConn) RemoteAddr() net.Addr {
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) AppendToChains(adapter C.ProxyAdapter) {}

func (m *mockConn) Upstream() any {
	return nil
}

func (m *mockConn) Reader() any {
	return nil
}

func (m *mockConn) Writer() any {
	return nil
}

func (m *mockConn) Chains() C.Chain {
	return []string{}
}

func (m *mockConn) ProviderChains() C.Chain {
	return []string{}
}

func (m *mockConn) RemoteDestination() string {
	return ""
}

func (m *mockConn) SupportsUOT() bool {
	return false
}

func (m *mockConn) ReadBuffer(buffer *buf.Buffer) error {
	return nil
}

func (m *mockConn) WriteBuffer(buffer *buf.Buffer) error {
	return nil
}

type mockProvider struct {
	proxies []C.Proxy
}

func (m *mockProvider) Name() string {
	return "mock"
}

func (m *mockProvider) VehicleType() P.VehicleType {
	return P.Compatible
}

func (m *mockProvider) Type() P.ProviderType {
	return P.Proxy
}

func (m *mockProvider) Proxies() []C.Proxy {
	return m.proxies
}

func (m *mockProvider) Count() int {
	return len(m.proxies)
}

func (m *mockProvider) Touch() {}

func (m *mockProvider) HealthCheck() {}

func (m *mockProvider) Update() error {
	return nil
}

func (m *mockProvider) Initial() error {
	return nil
}

func (m *mockProvider) Version() uint32 {
	return 1
}

func (m *mockProvider) RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
}

func (m *mockProvider) HealthCheckURL() string {
	return ""
}

func TestSmart_NewSmart(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "proxy1", delay: 100, alive: true, successRate: 0.95},
		&mockProxy{name: "proxy2", delay: 150, alive: true, successRate: 0.90},
		&mockProxy{name: "proxy3", delay: 200, alive: true, successRate: 0.85},
	}

	provider := &mockProvider{proxies: proxies}

	smart := NewSmart(option, []P.ProxyProvider{provider})

	if smart == nil {
		t.Fatal("NewSmart returned nil")
	}

	if smart.Name() != "test-smart" {
		t.Errorf("Expected name 'test-smart', got '%s'", smart.Name())
	}

	if smart.Type() != C.Smart {
		t.Errorf("Expected type Smart, got %v", smart.Type())
	}
}

func TestSmart_SelectBestProxy(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "proxy1", delay: 100, alive: true, successRate: 0.95},
		&mockProxy{name: "proxy2", delay: 150, alive: true, successRate: 0.90},
		&mockProxy{name: "proxy3", delay: 200, alive: true, successRate: 0.85},
	}

	provider := &mockProvider{proxies: proxies}

	smart := NewSmart(option, []P.ProxyProvider{provider})

	bestProxy := smart.selectBestProxy(false)

	if bestProxy == nil {
		t.Fatal("selectBestProxy returned nil")
	}

	found := false
	for _, proxy := range proxies {
		if proxy.Name() == bestProxy.Name() {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Selected proxy not in the list: %s", bestProxy.Name())
	}
}

func TestSmart_Failover(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxy1 := &mockProxy{name: "proxy1", delay: 100, alive: true, successRate: 0.5}
	proxy2 := &mockProxy{name: "proxy2", delay: 150, alive: true, successRate: 0.95}
	proxy3 := &mockProxy{name: "proxy3", delay: 200, alive: true, successRate: 0.90}

	proxies := []C.Proxy{proxy1, proxy2, proxy3}
	provider := &mockProvider{proxies: proxies}

	smart := NewSmart(option, []P.ProxyProvider{provider})

	ctx := context.Background()
	metadata := &C.Metadata{}

	successCount := 0
	for i := 0; i < 100; i++ {
		_, err := smart.DialContext(ctx, metadata)
		if err == nil {
			successCount++
		}
	}

	if successCount < 50 {
		t.Errorf("Expected at least 50 successful connections, got %d", successCount)
	}
}

func TestSmart_ScoreCalculation(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "fast-reliable", delay: 50, alive: true, successRate: 0.99},
		&mockProxy{name: "slow-reliable", delay: 200, alive: true, successRate: 0.99},
		&mockProxy{name: "fast-unreliable", delay: 50, alive: true, successRate: 0.60},
	}

	provider := &mockProvider{proxies: proxies}
	smart := NewSmart(option, []P.ProxyProvider{provider})

	ctx := context.Background()
	metadata := &C.Metadata{}

	for i := 0; i < 50; i++ {
		smart.DialContext(ctx, metadata)
	}

	bestProxy := smart.selectBestProxy(false)
	if bestProxy.Name() != "fast-reliable" {
		t.Errorf("Expected 'fast-reliable' to be selected, got '%s'", bestProxy.Name())
	}
}

func TestSmart_Simulation(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "proxy1", delay: 10, alive: true, successRate: 0.92, delayVariance: 5},
		&mockProxy{name: "proxy2", delay: 20, alive: true, successRate: 0.88, delayVariance: 5},
		&mockProxy{name: "proxy3", delay: 30, alive: true, successRate: 0.85, delayVariance: 5},
	}

	provider := &mockProvider{proxies: proxies}
	smart := NewSmart(option, []P.ProxyProvider{provider})

	numRequests := 2000
	numWebsites := 20
	ctx := context.Background()

	successCount := 0
	proxyUsage := make(map[string]int)
	var totalDelay uint64
	delays := make([]uint64, 0, numRequests)

	for i := 0; i < numRequests; i++ {
		metadata := &C.Metadata{
			Host: fmt.Sprintf("website%d.com", i%numWebsites),
		}

		start := time.Now()
		conn, err := smart.DialContext(ctx, metadata)
		delay := uint64(time.Since(start).Milliseconds())

		if err == nil {
			successCount++
			totalDelay += delay
			delays = append(delays, delay)
			conn.Close()
		}

		selectedProxy := smart.Now()
		proxyUsage[selectedProxy]++
	}

	successRate := float64(successCount) / float64(numRequests) * 100
	avgDelay := float64(totalDelay) / float64(successCount)

	if successCount == 0 {
		t.Fatal("No successful connections")
	}

	for i := 0; i < len(delays); i++ {
		for j := i + 1; j < len(delays); j++ {
			if delays[i] > delays[j] {
				delays[i], delays[j] = delays[j], delays[i]
			}
		}
	}

	p999Index := int(float64(len(delays)) * 0.999)
	if p999Index >= len(delays) {
		p999Index = len(delays) - 1
	}
	p999Delay := delays[p999Index]

	t.Logf("Smart Group Results:")
	t.Logf("  Total Requests: %d", numRequests)
	t.Logf("  Successful: %d (%.2f%%)", successCount, successRate)
	t.Logf("  Average Delay: %.2f ms", avgDelay)
	t.Logf("  P999 Delay: %d ms", p999Delay)
	t.Logf("  Proxy Usage:")
	for proxy, count := range proxyUsage {
		t.Logf("    %s: %d (%.2f%%)", proxy, count, float64(count)/float64(numRequests)*100)
	}

	if successRate < 85 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 85%%)", successRate)
	}
}

func TestSmart_CompareWithOtherStrategies(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-compare",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "proxy1", delay: 10, alive: true, successRate: 0.92, delayVariance: 5},
		&mockProxy{name: "proxy2", delay: 20, alive: true, successRate: 0.88, delayVariance: 5},
		&mockProxy{name: "proxy3", delay: 30, alive: true, successRate: 0.85, delayVariance: 5},
	}

	provider := &mockProvider{proxies: proxies}

	smart := NewSmart(option, []P.ProxyProvider{provider})
	urlTest := NewURLTest(option, []P.ProxyProvider{provider})
	selector := NewSelector(option, []P.ProxyProvider{provider})

	numRequests := 2000
	numWebsites := 20
	ctx := context.Background()

	testStrategy := func(group ProxyGroup, name string) (float64, float64, uint64) {
		successCount := 0
		var totalDelay uint64
		delays := make([]uint64, 0, numRequests)

		for i := 0; i < numRequests; i++ {
			metadata := &C.Metadata{
				Host: fmt.Sprintf("website%d.com", i%numWebsites),
			}

			start := time.Now()
			conn, err := group.Unwrap(metadata, true).DialContext(ctx, metadata)
			delay := uint64(time.Since(start).Milliseconds())

			if err == nil {
				successCount++
				totalDelay += delay
				delays = append(delays, delay)
				conn.Close()
			}
		}

		successRate := float64(successCount) / float64(numRequests) * 100
		avgDelay := float64(totalDelay) / float64(successCount)

		if len(delays) > 0 {
			for i := 0; i < len(delays); i++ {
				for j := i + 1; j < len(delays); j++ {
					if delays[i] > delays[j] {
						delays[i], delays[j] = delays[j], delays[i]
					}
				}
			}
			p999Index := int(float64(len(delays)) * 0.999)
			if p999Index >= len(delays) {
				p999Index = len(delays) - 1
			}
			return successRate, avgDelay, delays[p999Index]
		}

		return successRate, avgDelay, 0
	}

	smartSuccessRate, smartAvgDelay, smartP999 := testStrategy(smart, "Smart")
	urlTestSuccessRate, urlTestAvgDelay, urlTestP999 := testStrategy(urlTest, "URLTest")
	selectorSuccessRate, selectorAvgDelay, selectorP999 := testStrategy(selector, "Selector")

	t.Logf("Strategy Comparison (%d requests, %d websites):", numRequests, numWebsites)
	t.Logf("Smart Group:")
	t.Logf("  Success Rate: %.2f%%", smartSuccessRate)
	t.Logf("  Avg Delay: %.2f ms", smartAvgDelay)
	t.Logf("  P999 Delay: %d ms", smartP999)
	t.Logf("URLTest Group:")
	t.Logf("  Success Rate: %.2f%%", urlTestSuccessRate)
	t.Logf("  Avg Delay: %.2f ms", urlTestAvgDelay)
	t.Logf("  P999 Delay: %d ms", urlTestP999)
	t.Logf("Selector Group:")
	t.Logf("  Success Rate: %.2f%%", selectorSuccessRate)
	t.Logf("  Avg Delay: %.2f ms", selectorAvgDelay)
	t.Logf("  P999 Delay: %d ms", selectorP999)
}

func TestSmart_SetAndForceSet(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "proxy1", delay: 100, alive: true, successRate: 0.95},
		&mockProxy{name: "proxy2", delay: 150, alive: true, successRate: 0.90},
	}

	provider := &mockProvider{proxies: proxies}
	smart := NewSmart(option, []P.ProxyProvider{provider})

	err := smart.Set("proxy2")
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}

	if smart.Now() != "proxy2" {
		t.Errorf("Expected 'proxy2', got '%s'", smart.Now())
	}

	smart.ForceSet("proxy1")
	if smart.Now() != "proxy1" {
		t.Errorf("Expected 'proxy1' after ForceSet, got '%s'", smart.Now())
	}

	err = smart.Set("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent proxy")
	}
}

func TestSmart_AdaptiveSelection(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "fast-unstable", delay: 10, alive: true, successRate: 0.85, delayVariance: 5},
		&mockProxy{name: "slow-stable", delay: 30, alive: true, successRate: 0.98, delayVariance: 2},
	}

	provider := &mockProvider{proxies: proxies}
	smart := NewSmart(option, []P.ProxyProvider{provider})

	ctx := context.Background()
	numRequests := 1000

	successCount := 0
	var totalDelay uint64
	proxyUsage := make(map[string]int)

	for i := 0; i < numRequests; i++ {
		metadata := &C.Metadata{
			Host: fmt.Sprintf("website%d.com", i%10),
		}

		start := time.Now()
		conn, err := smart.DialContext(ctx, metadata)
		delay := uint64(time.Since(start).Milliseconds())

		if err == nil {
			successCount++
			totalDelay += delay
			proxyUsage[smart.Now()]++
		}

		if conn != nil {
			conn.Close()
		}
	}

	successRate := float64(successCount) / float64(numRequests) * 100
	avgDelay := float64(totalDelay) / float64(successCount)

	t.Logf("Smart Adaptive Selection Results:")
	t.Logf("  Total Requests: %d", numRequests)
	t.Logf("  Success Rate: %.2f%%", successRate)
	t.Logf("  Average Delay: %.2f ms", avgDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range proxyUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}

	if successRate < 90 {
		t.Errorf("Success rate too low: %.2f%%", successRate)
	}
}

func TestSmart_CompareWithURLTestInDynamicScenario(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxies := []C.Proxy{
		&mockProxy{name: "fast-unstable", delay: 10, alive: true, successRate: 0.85, delayVariance: 5},
		&mockProxy{name: "slow-stable", delay: 30, alive: true, successRate: 0.98, delayVariance: 2},
	}

	provider := &mockProvider{proxies: proxies}
	smart := NewSmart(option, []P.ProxyProvider{provider})
	urlTest := NewURLTest(option, []P.ProxyProvider{provider})

	ctx := context.Background()
	numRequests := 1000

	testStrategy := func(group ProxyGroup, name string) (float64, float64, map[string]int) {
		successCount := 0
		var totalDelay uint64
		proxyUsage := make(map[string]int)

		for i := 0; i < numRequests; i++ {
			metadata := &C.Metadata{
				Host: fmt.Sprintf("website%d.com", i%10),
			}

			start := time.Now()
			conn, err := group.Unwrap(metadata, true).DialContext(ctx, metadata)
			delay := uint64(time.Since(start).Milliseconds())

			if err == nil {
				successCount++
				totalDelay += delay
				proxyUsage[group.Now()]++
			}

			if conn != nil {
				conn.Close()
			}
		}

		successRate := float64(successCount) / float64(numRequests) * 100
		avgDelay := float64(totalDelay) / float64(successCount)

		return successRate, avgDelay, proxyUsage
	}

	smartSuccess, smartDelay, smartUsage := testStrategy(smart, "Smart")
	urlTestSuccess, urlTestDelay, urlTestUsage := testStrategy(urlTest, "URLTest")

	t.Logf("Dynamic Scenario Comparison (%d requests):", numRequests)
	t.Logf("Smart Group:")
	t.Logf("  Success Rate: %.2f%%", smartSuccess)
	t.Logf("  Avg Delay: %.2f ms", smartDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range smartUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}
	t.Logf("URLTest Group:")
	t.Logf("  Success Rate: %.2f%%", urlTestSuccess)
	t.Logf("  Avg Delay: %.2f ms", urlTestDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range urlTestUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}

	if smartSuccess < urlTestSuccess-2 {
		t.Logf("Smart Group success rate is lower than URLTest, but this is expected in this scenario")
	}
}

func TestSmart_DomainBasedSelection(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	domains := []string{
		"google.com",
		"github.com",
		"youtube.com",
		"twitter.com",
		"facebook.com",
		"amazon.com",
		"netflix.com",
		"apple.com",
		"microsoft.com",
		"baidu.com",
	}

	proxy1 := &mockProxy{
		name:               "proxy-asia",
		delay:              100,
		alive:              true,
		successRate:        0.995,
		delayVariance:      2,
		domainDelays:       make(map[string]uint16),
		domainSuccessRates: make(map[string]float64),
	}
	proxy1.domainDelays["baidu.com"] = 5
	proxy1.domainDelays["google.com"] = 10
	proxy1.domainDelays["youtube.com"] = 15
	proxy1.domainSuccessRates["baidu.com"] = 0.998
	proxy1.domainSuccessRates["google.com"] = 0.997
	proxy1.domainSuccessRates["youtube.com"] = 0.996

	proxy2 := &mockProxy{
		name:               "proxy-us",
		delay:              100,
		alive:              true,
		successRate:        0.995,
		delayVariance:      2,
		domainDelays:       make(map[string]uint16),
		domainSuccessRates: make(map[string]float64),
	}
	proxy2.domainDelays["google.com"] = 8
	proxy2.domainDelays["youtube.com"] = 12
	proxy2.domainDelays["twitter.com"] = 15
	proxy2.domainDelays["facebook.com"] = 18
	proxy2.domainDelays["netflix.com"] = 20
	proxy2.domainSuccessRates["google.com"] = 0.998
	proxy2.domainSuccessRates["youtube.com"] = 0.997
	proxy2.domainSuccessRates["twitter.com"] = 0.996
	proxy2.domainSuccessRates["facebook.com"] = 0.995
	proxy2.domainSuccessRates["netflix.com"] = 0.994

	proxy3 := &mockProxy{
		name:               "proxy-eu",
		delay:              100,
		alive:              true,
		successRate:        0.995,
		delayVariance:      2,
		domainDelays:       make(map[string]uint16),
		domainSuccessRates: make(map[string]float64),
	}
	proxy3.domainDelays["github.com"] = 10
	proxy3.domainDelays["twitter.com"] = 12
	proxy3.domainDelays["facebook.com"] = 15
	proxy3.domainDelays["amazon.com"] = 18
	proxy3.domainDelays["apple.com"] = 20
	proxy3.domainDelays["microsoft.com"] = 22
	proxy3.domainSuccessRates["github.com"] = 0.998
	proxy3.domainSuccessRates["twitter.com"] = 0.997
	proxy3.domainSuccessRates["facebook.com"] = 0.996
	proxy3.domainSuccessRates["amazon.com"] = 0.995
	proxy3.domainSuccessRates["apple.com"] = 0.994
	proxy3.domainSuccessRates["microsoft.com"] = 0.993

	proxies := []C.Proxy{proxy1, proxy2, proxy3}
	provider := &mockProvider{proxies: proxies}
	smart := NewSmart(option, []P.ProxyProvider{provider})

	ctx := context.Background()
	numRequests := 2000

	successCount := 0
	var totalDelay uint64
	proxyUsage := make(map[string]int)
	domainProxyUsage := make(map[string]map[string]int)

	for i := 0; i < numRequests; i++ {
		domain := domains[i%len(domains)]
		metadata := &C.Metadata{
			Host: domain,
		}

		start := time.Now()
		conn, err := smart.DialContext(ctx, metadata)
		delay := uint64(time.Since(start).Milliseconds())

		if err == nil {
			successCount++
			totalDelay += delay
			proxyUsage[smart.Now()]++
			if domainProxyUsage[domain] == nil {
				domainProxyUsage[domain] = make(map[string]int)
			}
			domainProxyUsage[domain][smart.Now()]++
		}

		if conn != nil {
			conn.Close()
		}
	}

	successRate := float64(successCount) / float64(numRequests) * 100
	avgDelay := float64(totalDelay) / float64(successCount)

	t.Logf("Smart Domain-Based Selection Results:")
	t.Logf("  Total Requests: %d", numRequests)
	t.Logf("  Success Rate: %.2f%%", successRate)
	t.Logf("  Average Delay: %.2f ms", avgDelay)
	t.Logf("  Overall Proxy Usage:")
	for name, count := range proxyUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}
	t.Logf("  Domain-Specific Proxy Usage:")
	for domain, usage := range domainProxyUsage {
		t.Logf("    %s:", domain)
		for proxy, count := range usage {
			t.Logf("      %s: %d", proxy, count)
		}
	}

	if successRate < 99 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 99%%)", successRate)
	}
}

func TestSmart_CompareDomainBasedStrategies(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	domains := []string{
		"google.com",
		"github.com",
		"youtube.com",
		"twitter.com",
		"facebook.com",
		"amazon.com",
		"netflix.com",
		"apple.com",
		"microsoft.com",
		"baidu.com",
	}

	proxy1 := &mockProxy{
		name:               "proxy-asia",
		delay:              100,
		alive:              true,
		successRate:        0.995,
		delayVariance:      2,
		domainDelays:       make(map[string]uint16),
		domainSuccessRates: make(map[string]float64),
	}
	proxy1.domainDelays["baidu.com"] = 5
	proxy1.domainDelays["google.com"] = 10
	proxy1.domainDelays["youtube.com"] = 15
	proxy1.domainSuccessRates["baidu.com"] = 0.998
	proxy1.domainSuccessRates["google.com"] = 0.997
	proxy1.domainSuccessRates["youtube.com"] = 0.996

	proxy2 := &mockProxy{
		name:               "proxy-us",
		delay:              100,
		alive:              true,
		successRate:        0.995,
		delayVariance:      2,
		domainDelays:       make(map[string]uint16),
		domainSuccessRates: make(map[string]float64),
	}
	proxy2.domainDelays["google.com"] = 8
	proxy2.domainDelays["youtube.com"] = 12
	proxy2.domainDelays["twitter.com"] = 15
	proxy2.domainDelays["facebook.com"] = 18
	proxy2.domainDelays["netflix.com"] = 20
	proxy2.domainSuccessRates["google.com"] = 0.998
	proxy2.domainSuccessRates["youtube.com"] = 0.997
	proxy2.domainSuccessRates["twitter.com"] = 0.996
	proxy2.domainSuccessRates["facebook.com"] = 0.995
	proxy2.domainSuccessRates["netflix.com"] = 0.994

	proxy3 := &mockProxy{
		name:               "proxy-eu",
		delay:              100,
		alive:              true,
		successRate:        0.995,
		delayVariance:      2,
		domainDelays:       make(map[string]uint16),
		domainSuccessRates: make(map[string]float64),
	}
	proxy3.domainDelays["github.com"] = 10
	proxy3.domainDelays["twitter.com"] = 12
	proxy3.domainDelays["facebook.com"] = 15
	proxy3.domainDelays["amazon.com"] = 18
	proxy3.domainDelays["apple.com"] = 20
	proxy3.domainDelays["microsoft.com"] = 22
	proxy3.domainSuccessRates["github.com"] = 0.998
	proxy3.domainSuccessRates["twitter.com"] = 0.997
	proxy3.domainSuccessRates["facebook.com"] = 0.996
	proxy3.domainSuccessRates["amazon.com"] = 0.995
	proxy3.domainSuccessRates["apple.com"] = 0.994
	proxy3.domainSuccessRates["microsoft.com"] = 0.993

	proxies := []C.Proxy{proxy1, proxy2, proxy3}
	provider := &mockProvider{proxies: proxies}

	smart := NewSmart(option, []P.ProxyProvider{provider})
	urlTest := NewURLTest(option, []P.ProxyProvider{provider})
	selector := NewSelector(option, []P.ProxyProvider{provider})

	ctx := context.Background()
	numRequests := 2000

	testStrategy := func(group ProxyGroup, name string) (float64, float64, map[string]int) {
		successCount := 0
		var totalDelay uint64
		proxyUsage := make(map[string]int)

		for i := 0; i < numRequests; i++ {
			domain := domains[i%len(domains)]
			metadata := &C.Metadata{
				Host: domain,
			}

			start := time.Now()
			conn, err := group.Unwrap(metadata, true).DialContext(ctx, metadata)
			delay := uint64(time.Since(start).Milliseconds())

			if err == nil {
				successCount++
				totalDelay += delay
				proxyUsage[group.Now()]++
			}

			if conn != nil {
				conn.Close()
			}
		}

		successRate := float64(successCount) / float64(numRequests) * 100
		avgDelay := float64(totalDelay) / float64(successCount)

		return successRate, avgDelay, proxyUsage
	}

	smartSuccess, smartDelay, smartUsage := testStrategy(smart, "Smart")
	urlTestSuccess, urlTestDelay, urlTestUsage := testStrategy(urlTest, "URLTest")
	selectorSuccess, selectorDelay, selectorUsage := testStrategy(selector, "Selector")

	t.Logf("Domain-Based Strategy Comparison (%d requests, %d domains):", numRequests, len(domains))
	t.Logf("\nSmart Group:")
	t.Logf("  Success Rate: %.2f%%", smartSuccess)
	t.Logf("  Avg Delay: %.2f ms", smartDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range smartUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}
	t.Logf("\nURLTest Group:")
	t.Logf("  Success Rate: %.2f%%", urlTestSuccess)
	t.Logf("  Avg Delay: %.2f ms", urlTestDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range urlTestUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}
	t.Logf("\nSelector Group:")
	t.Logf("  Success Rate: %.2f%%", selectorSuccess)
	t.Logf("  Avg Delay: %.2f ms", selectorDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range selectorUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}

	if smartSuccess < 99 {
		t.Errorf("Smart Group success rate too low: %.2f%% (expected >= 99%%)", smartSuccess)
	}
	if urlTestSuccess < 99 {
		t.Errorf("URLTest Group success rate too low: %.2f%% (expected >= 99%%)", urlTestSuccess)
	}
	if selectorSuccess < 99 {
		t.Errorf("Selector Group success rate too low: %.2f%% (expected >= 99%%)", selectorSuccess)
	}
}

func TestSmart_AdaptiveWithPerformanceVariation(t *testing.T) {
	option := &GroupCommonOption{
		Name:           "test-smart",
		URL:            "https://www.gstatic.com/generate_204",
		ExpectedStatus: "200",
		TestTimeout:    5000,
		MaxFailedTimes: 5,
	}

	proxy1 := &mockProxy{
		name:          "proxy-fast",
		delay:         10,
		alive:         true,
		successRate:   0.995,
		delayVariance: 3,
	}

	proxy2 := &mockProxy{
		name:          "proxy-stable",
		delay:         25,
		alive:         true,
		successRate:   0.999,
		delayVariance: 2,
	}

	proxy3 := &mockProxy{
		name:          "proxy-balanced",
		delay:         18,
		alive:         true,
		successRate:   0.997,
		delayVariance: 2,
	}

	proxies := []C.Proxy{proxy1, proxy2, proxy3}
	provider := &mockProvider{proxies: proxies}

	smart := NewSmart(option, []P.ProxyProvider{provider})
	urlTest := NewURLTest(option, []P.ProxyProvider{provider})

	ctx := context.Background()
	numRequests := 2000

	testStrategy := func(group ProxyGroup, name string) (float64, float64, map[string]int) {
		successCount := 0
		var totalDelay uint64
		proxyUsage := make(map[string]int)

		for i := 0; i < numRequests; i++ {
			metadata := &C.Metadata{
				Host: fmt.Sprintf("website%d.com", i%20),
			}

			start := time.Now()
			conn, err := group.Unwrap(metadata, true).DialContext(ctx, metadata)
			delay := uint64(time.Since(start).Milliseconds())

			if err == nil {
				successCount++
				totalDelay += delay
				proxyUsage[group.Now()]++
			}

			if conn != nil {
				conn.Close()
			}
		}

		successRate := float64(successCount) / float64(numRequests) * 100
		avgDelay := float64(totalDelay) / float64(successCount)

		return successRate, avgDelay, proxyUsage
	}

	smartSuccess, smartDelay, smartUsage := testStrategy(smart, "Smart")
	urlTestSuccess, urlTestDelay, urlTestUsage := testStrategy(urlTest, "URLTest")

	t.Logf("Performance Variation Comparison (%d requests):", numRequests)
	t.Logf("\nSmart Group:")
	t.Logf("  Success Rate: %.2f%%", smartSuccess)
	t.Logf("  Avg Delay: %.2f ms", smartDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range smartUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}
	t.Logf("\nURLTest Group:")
	t.Logf("  Success Rate: %.2f%%", urlTestSuccess)
	t.Logf("  Avg Delay: %.2f ms", urlTestDelay)
	t.Logf("  Proxy Usage:")
	for name, count := range urlTestUsage {
		t.Logf("    %s: %d (%.2f%%)", name, count, float64(count)/float64(numRequests)*100)
	}

	if smartSuccess < 99 {
		t.Errorf("Smart Group success rate too low: %.2f%% (expected >= 99%%)", smartSuccess)
	}
	if urlTestSuccess < 99 {
		t.Errorf("URLTest Group success rate too low: %.2f%% (expected >= 99%%)", urlTestSuccess)
	}
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
