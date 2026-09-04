package outboundgroup

import (
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type latencyTestProxy struct {
	C.Proxy
	name  string
	alive bool
	delay uint16
}

func (p *latencyTestProxy) Name() string {
	return p.name
}

func (p *latencyTestProxy) AliveForTestUrl(string) bool {
	return p.alive
}

func (p *latencyTestProxy) LastDelayForTestUrl(string) uint16 {
	if !p.alive || p.delay == 0 {
		return math.MaxUint16
	}
	return p.delay
}

func testMetadata(id int) *C.Metadata {
	return &C.Metadata{Host: fmt.Sprintf("192.0.2.%d", id%254+1)}
}

func TestInsertTopLatencyCandidate(t *testing.T) {
	candidates := []latencyCandidate{}
	for _, candidate := range []latencyCandidate{
		{name: "slow", delay: 90},
		{name: "fast", delay: 20},
		{name: "middle", delay: 50},
		{name: "slower", delay: 70},
	} {
		candidates = insertTopLatencyCandidate(candidates, candidate, 3)
	}

	require.Equal(t, []string{"fast", "middle", "slower"}, []string{
		candidates[0].name,
		candidates[1].name,
		candidates[2].name,
	})
}

func TestInverseLatencyWeighting(t *testing.T) {
	candidates := []latencyCandidate{
		{name: "fast", delay: 30},
		{name: "middle", delay: 60},
		{name: "slow", delay: 120},
	}
	counts := map[string]int{}
	const samples = 20000
	for key := uint64(1); key <= samples; key++ {
		counts[selectLatencyWeightedCandidate(candidates, key).name]++
	}

	// Inverse latency gives an expected ratio of 4:2:1. The bounds are wide
	// enough to avoid flakiness while still detecting an unweighted selector.
	require.InDelta(t, 4.0/7.0, float64(counts["fast"])/samples, 0.03)
	require.InDelta(t, 2.0/7.0, float64(counts["middle"])/samples, 0.03)
	require.InDelta(t, 1.0/7.0, float64(counts["slow"])/samples, 0.03)
}

func TestLatencyWeightedStickySessionConcurrentAccess(t *testing.T) {
	proxies := []C.Proxy{
		&latencyTestProxy{name: "fast", alive: true, delay: 20},
		&latencyTestProxy{name: "middle", alive: true, delay: 40},
		&latencyTestProxy{name: "slow", alive: true, delay: 80},
	}
	strategy := strategyStickySessionsLatencyWeighted("test", 3)

	var waitGroup sync.WaitGroup
	for i := 1; i <= 100; i++ {
		waitGroup.Add(1)
		go func(id int) {
			defer waitGroup.Done()
			metadata := testMetadata(id)
			first := strategy(proxies, metadata, true)
			for j := 0; j < 10; j++ {
				if selected := strategy(proxies, metadata, true); selected.Name() != first.Name() {
					t.Errorf("session changed from %s to %s", first.Name(), selected.Name())
					return
				}
			}
		}(i)
	}
	waitGroup.Wait()
}

func TestLatencyWeightedStickySessionUsesStableProxyIdentity(t *testing.T) {
	fast := &latencyTestProxy{name: "fast", alive: true, delay: 20}
	slow := &latencyTestProxy{name: "slow", alive: true, delay: 100}
	strategy := strategyStickySessionsLatencyWeighted("test", 2)
	metadata := testMetadata(1)

	first := strategy([]C.Proxy{fast, slow}, metadata, true)
	fast.delay, slow.delay = 200, 10
	second := strategy([]C.Proxy{slow, fast}, metadata, true)
	require.Equal(t, first.Name(), second.Name())

	if first.Name() == fast.Name() {
		fast.alive = false
	} else {
		slow.alive = false
	}
	third := strategy([]C.Proxy{fast, slow}, metadata, true)
	require.NotEqual(t, first.Name(), third.Name())
}

func TestLatencyWeightedStickySessionTopNAndUnknownDelay(t *testing.T) {
	fast := &latencyTestProxy{name: "fast", alive: true, delay: 20}
	middle := &latencyTestProxy{name: "middle", alive: true, delay: 40}
	slow := &latencyTestProxy{name: "slow", alive: true, delay: 200}
	strategy := strategyStickySessionsLatencyWeighted("test", 2)

	for i := 1; i <= 100; i++ {
		require.NotEqual(t, slow.Name(), strategy([]C.Proxy{slow, middle, fast}, testMetadata(i), true).Name())
	}

	unknownA := &latencyTestProxy{name: "unknown-a", alive: true}
	unknownB := &latencyTestProxy{name: "unknown-b", alive: true}
	dead := &latencyTestProxy{name: "dead", alive: false, delay: 1}
	selected := strategyStickySessionsLatencyWeighted("test", 2)(
		[]C.Proxy{dead, unknownA, unknownB}, testMetadata(200), true,
	)
	require.Contains(t, []string{unknownA.Name(), unknownB.Name()}, selected.Name())
}

func TestLoadBalanceLatencyWeightingValidation(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
	decoded := LoadBalanceOption{}
	require.NoError(t, decoder.Decode(map[string]any{
		"strategy":  "sticky-sessions",
		"weighting": "inverse-latency",
		"top-n":     3,
	}, &decoded))
	require.Equal(t, LoadBalanceOption{
		Strategy:  "sticky-sessions",
		Weighting: "inverse-latency",
		TopN:      3,
	}, decoded)

	lb, err := NewLoadBalance(GroupCommonOption{}, decoded, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "inverse-latency", lb.weighting)
	require.Equal(t, 3, lb.topN)

	_, err = NewLoadBalance(GroupCommonOption{}, LoadBalanceOption{
		Strategy: "sticky-sessions",
		TopN:     3,
	}, nil, nil)
	require.EqualError(t, err, "top-n requires weighting")

	_, err = NewLoadBalance(GroupCommonOption{}, LoadBalanceOption{
		Strategy:  "round-robin",
		Weighting: "inverse-latency",
	}, nil, nil)
	require.EqualError(t, err, "weighting is only supported by sticky-sessions")

	_, err = NewLoadBalance(GroupCommonOption{}, LoadBalanceOption{
		Strategy:  "sticky-sessions",
		Weighting: "unknown",
	}, nil, nil)
	require.EqualError(t, err, "unsupported weighting: unknown")
}
