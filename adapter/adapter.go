package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/queue"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

var UnifiedDelay = atomic.NewBool(false)

const (
	defaultHistoriesNum      = 10
	defaultSpeedHistoriesNum = 120
	defaultTestResultsNum    = 20
	speedStaleThreshold      = 30 * time.Second
	speedDecayLambda         = 0.001
)

type internalProxyState struct {
	alive   atomic.Bool
	history *queue.Queue[C.DelayHistory]
}

type Proxy struct {
	C.ProxyAdapter
	alive   atomic.Bool
	history *queue.Queue[C.DelayHistory]
	extra   xsync.Map[string, *internalProxyState]

	peakSpeed    atomic.Uint64
	peakAt       atomic.Int64
	currentSpeed atomic.Uint64
	currentAt    atomic.Int64

	speedHistoryMu sync.Mutex
	speedHistory   []C.SpeedHistory

	testResultsMu sync.Mutex
	testResults   []TestResult
}

type TestResult struct {
	At      time.Time
	Success bool
}

// Adapter implements C.Proxy
func (p *Proxy) Adapter() C.ProxyAdapter {
	return p.ProxyAdapter
}

// AliveForTestUrl implements C.Proxy
func (p *Proxy) AliveForTestUrl(url string) bool {
	if state, ok := p.extra.Load(url); ok {
		return state.alive.Load()
	}

	return p.alive.Load()
}

// DialContext implements C.ProxyAdapter
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := p.ProxyAdapter.DialContext(ctx, metadata)
	return conn, err
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata)
	return pc, err
}

// DelayHistory implements C.Proxy
func (p *Proxy) DelayHistory() []C.DelayHistory {
	queueM := p.history.Copy()
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// DelayHistoryForTestUrl implements C.Proxy
func (p *Proxy) DelayHistoryForTestUrl(url string) []C.DelayHistory {
	var queueM []C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		queueM = state.history.Copy()
	}
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// ExtraDelayHistories return all delay histories for each test URL
// implements C.Proxy
func (p *Proxy) ExtraDelayHistories() map[string]C.ProxyState {
	histories := map[string]C.ProxyState{}

	p.extra.Range(func(k string, v *internalProxyState) bool {
		testUrl := k
		state := v

		queueM := state.history.Copy()
		var history []C.DelayHistory

		for _, item := range queueM {
			history = append(history, item)
		}

		histories[testUrl] = C.ProxyState{
			Alive:   state.alive.Load(),
			History: history,
		}
		return true
	})
	return histories
}

// LastDelayForTestUrl return last history record of the specified URL. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastDelayForTestUrl(url string) (delay uint16) {
	var maxDelay uint16 = 0xffff

	alive := false
	var history C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		alive = state.alive.Load()
		history = state.history.Last()
	}

	if !alive || history.Delay == 0 {
		return maxDelay
	}
	return history.Delay
}

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["extra"] = p.ExtraDelayHistories()
	mapping["alive"] = p.alive.Load()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	mapping["uot"] = p.SupportUOT()

	proxyInfo := p.ProxyInfo()
	mapping["xudp"] = proxyInfo.XUDP
	mapping["tfo"] = proxyInfo.TFO
	mapping["mptcp"] = proxyInfo.MPTCP
	mapping["smux"] = proxyInfo.SMUX
	mapping["interface"] = proxyInfo.Interface
	mapping["routing-mark"] = proxyInfo.RoutingMark
	mapping["provider-name"] = proxyInfo.ProviderName
	mapping["dialer-proxy"] = proxyInfo.DialerProxy

	return json.Marshal(mapping)
}

// URLTest get the delay for the specified URL
// implements C.Proxy
func (p *Proxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, err error) {
	var satisfied bool

	defer func() {
		alive := err == nil
		record := C.DelayHistory{Time: time.Now()}
		if alive {
			record.Delay = t
		}

		p.alive.Store(alive)
		p.history.Put(record)
		if p.history.Len() > defaultHistoriesNum {
			p.history.Pop()
		}

		state, _ := p.extra.LoadOrStoreFn(url, func() *internalProxyState {
			return &internalProxyState{
				history: queue.New[C.DelayHistory](defaultHistoriesNum),
				alive:   atomic.NewBool(true),
			}
		})

		if !satisfied {
			record.Delay = 0
			alive = false
		}

		state.alive.Store(alive)
		state.history.Put(record)
		if state.history.Len() > defaultHistoriesNum {
			state.history.Pop()
		}

	}()

	unifiedDelay := UnifiedDelay.Load()

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := time.Now()
	instance, err := p.DialContext(ctx, &addr)
	if err != nil {
		return
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return
	}

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	defer client.CloseIdleConnections()

	resp, err := client.Do(req)

	if err != nil {
		return
	}

	_ = resp.Body.Close()

	if unifiedDelay {
		second := time.Now()
		var ignoredErr error
		var secondResp *http.Response
		secondResp, ignoredErr = client.Do(req)
		if ignoredErr == nil {
			resp = secondResp
			_ = resp.Body.Close()
			start = second
		} else {
			if strings.HasPrefix(url, "http://") {
				log.Errorln("%s failed to get the second response from %s: %v", p.Name(), url, ignoredErr)
				log.Warnln("It is recommended to use HTTPS for provider.health-check.url and group.url to ensure better reliability. Due to some proxy providers hijacking test addresses and not being compatible with repeated HEAD requests, using HTTP may result in failed tests.")
			}
		}
	}

	satisfied = resp != nil && (expectedStatus == nil || expectedStatus.Check(uint16(resp.StatusCode)))
	t = uint16(time.Since(start) / time.Millisecond)
	return
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{
		ProxyAdapter: adapter,
		history:      queue.New[C.DelayHistory](defaultHistoriesNum),
		alive:        atomic.NewBool(true),
	}
}

// PushSpeed implements C.Proxy - updates current speed and peak if exceeds decayed peak
func (p *Proxy) PushSpeed(speed uint64) {
	if speed == 0 {
		return
	}
	now := time.Now()
	p.currentSpeed.Store(speed)
	p.currentAt.Store(now.UnixNano())

	peak := p.peakSpeed.Load()
	peakAt := time.Unix(0, p.peakAt.Load())
	decayedPeak := uint64(float64(peak) * math.Exp(-speedDecayLambda*now.Sub(peakAt).Seconds()))
	if speed >= decayedPeak {
		p.peakSpeed.Store(speed)
		p.peakAt.Store(now.UnixNano())
	}

	p.speedHistoryMu.Lock()
	p.speedHistory = append(p.speedHistory, C.SpeedHistory{Time: now, Speed: speed})
	if len(p.speedHistory) > defaultSpeedHistoriesNum {
		p.speedHistory = p.speedHistory[1:]
	}
	p.speedHistoryMu.Unlock()
}

// LastSpeed implements C.Proxy - returns fresh speed or 0 if stale
func (p *Proxy) LastSpeed() uint64 {
	at := time.Unix(0, p.currentAt.Load())
	if at.IsZero() || time.Since(at) > speedStaleThreshold {
		return 0
	}
	return p.currentSpeed.Load()
}

// EffectiveSpeed implements C.Proxy - max(decayed peak, fresh current)
func (p *Proxy) EffectiveSpeed() uint64 {
	current := p.LastSpeed()
	peak := uint64(float64(p.peakSpeed.Load()) * math.Exp(-speedDecayLambda*time.Since(time.Unix(0, p.peakAt.Load())).Seconds()))
	if peak > current {
		return peak
	}
	return current
}

// SpeedHistory implements C.Proxy
func (p *Proxy) SpeedHistory() []C.SpeedHistory {
	p.speedHistoryMu.Lock()
	out := make([]C.SpeedHistory, len(p.speedHistory))
	copy(out, p.speedHistory)
	p.speedHistoryMu.Unlock()
	return out
}

// PushTestResult implements C.Proxy - record test result for packet loss calculation
func (p *Proxy) PushTestResult(url string, success bool) {
	p.testResultsMu.Lock()
	p.testResults = append(p.testResults, TestResult{At: time.Now(), Success: success})
	if len(p.testResults) > defaultTestResultsNum {
		p.testResults = p.testResults[1:]
	}
	p.testResultsMu.Unlock()
}

// PacketLossRate implements C.Proxy - calculate loss rate from recent test results
func (p *Proxy) PacketLossRate(url string) float64 {
	p.testResultsMu.Lock()
	defer p.testResultsMu.Unlock()
	if len(p.testResults) == 0 {
		return 0
	}
	fails := 0
	for _, r := range p.testResults {
		if !r.Success {
			fails++
		}
	}
	return float64(fails) / float64(len(p.testResults))
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	err = addr.SetRemoteAddress(net.JoinHostPort(u.Hostname(), port))
	return
}
