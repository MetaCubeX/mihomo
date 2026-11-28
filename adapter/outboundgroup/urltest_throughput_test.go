package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

type speedProxy struct {
	C.Proxy
	name  string
	alive bool
	delay uint16
	speed uint64
}

func (p *speedProxy) Name() string                      { return p.name }
func (p *speedProxy) AliveForTestUrl(string) bool       { return p.alive }
func (p *speedProxy) LastDelayForTestUrl(string) uint16 { return p.delay }
func (p *speedProxy) LastSpeedForTestUrl(string) (C.SpeedHistory, bool) {
	return C.SpeedHistory{Time: time.Now(), Speed: p.speed}, p.speed > 0
}

func TestThroughputOption(t *testing.T) {
	opt, err := newThroughputOption(URLTestOption{})
	require.NoError(t, err)
	require.Nil(t, opt)

	_, err = newThroughputOption(URLTestOption{Strategy: "throughput"})
	require.ErrorIs(t, err, errThroughputURL)

	_, err = newThroughputOption(URLTestOption{Strategy: "fastest"})
	require.Error(t, err)

	tolerance := uint8(100)
	_, err = newThroughputOption(URLTestOption{Strategy: "throughput", ThroughputURL: "https://example.com", ThroughputTolerance: &tolerance})
	require.Error(t, err)

	opt, err = newThroughputOption(URLTestOption{Strategy: "throughput", ThroughputURL: "https://example.com"})
	require.NoError(t, err)
	require.Equal(t, 3*time.Second, opt.duration)
	require.EqualValues(t, defaultThroughputMaxBytes, opt.maxBytes)
	require.Equal(t, time.Hour, opt.interval)
	require.EqualValues(t, defaultThroughputTolerance, opt.tolerance)

	tolerance = 0
	opt, err = newThroughputOption(URLTestOption{Strategy: "throughput", ThroughputURL: "https://example.com", ThroughputTolerance: &tolerance})
	require.NoError(t, err)
	require.Zero(t, opt.tolerance)
}

func TestThroughputPick(t *testing.T) {
	tester := &throughputTester{throughputOption: &throughputOption{url: "https://example.com", tolerance: 10}}

	slow := &speedProxy{name: "slow", alive: true, delay: 50, speed: 1_000_000}
	fast := &speedProxy{name: "fast", alive: true, delay: 300, speed: 5_000_000}
	near := &speedProxy{name: "near", alive: true, delay: 100, speed: 4_600_000}
	dead := &speedProxy{name: "dead", alive: false, delay: 10, speed: 9_000_000}
	untested := &speedProxy{name: "untested", alive: true, delay: 5}

	require.Nil(t, tester.pick([]C.Proxy{untested}, testUrl), "fall back to latency without results")
	require.Equal(t, fast, tester.pick([]C.Proxy{slow, fast, dead, untested}, testUrl), "fastest alive proxy wins")
	require.Equal(t, near, tester.pick([]C.Proxy{slow, fast, near}, testUrl), "lower latency wins within tolerance")

	tester.tolerance = 0
	require.Equal(t, fast, tester.pick([]C.Proxy{slow, fast, near}, testUrl), "no tie-break with zero tolerance")
}
