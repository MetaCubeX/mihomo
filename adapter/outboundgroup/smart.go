package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

const (
	// 速度归一化参考值（P90 锚定）
	speedRefFloor   = 4 * 1024 * 1024  // 4 MiB/s，样本不足时的地板值，新节点达到此速度即可拿满分
	speedRefCeiling = 32 * 1024 * 1024 // 32 MiB/s，P90 上限，防止快网络中速度差异被过度放大
	minSpeedSamples = 3                // 计算 P90 所需的最小速度样本数，不足时用 floor 保底

	// EMA 基线更新
	baselineAlpha      = 0.20 // 指数移动平均系数，新样本权重 20%，历史权重 80%
	baselineMinSamples = 3    // 建立基线所需的最小成功样本数，此前用算术平均 bootstrap
	spikeIgnoreFactor  = 3.0  // 异常值忽略因子，延迟 > 基线×3 视为 spike 不更新基线
	baselineMaxStepUp  = 1.25 // 基线单次最大上涨比例 25%，防止 spike 缓慢污染基线
	reseedHighStreak   = 5    // 连续高延迟次数触发中位数重校准，说明网络环境真的变了

	// 退化检测与恢复
	degradeFactor    = 1.50 // 退化因子，延迟 > 基线×1.5 标记退化
	recoverFactor    = 1.20 // 恢复因子，延迟 ≤ 基线×1.2 才可清除退化（滞后防抖）
	recoverSuccesses = 2    // 清除退化所需连续成功次数
	degradePenalty   = 0.5  // 退化节点评分惩罚值（加到最终 score 上）

	// 评分权重（默认值，可在 YAML 中覆盖）
	defaultWeightDelay = 0.3 // 延迟权重
	defaultWeightLoss  = 0.3 // 丢包率权重
	defaultWeightSpeed = 0.4 // 速度权重

	// 其他默认参数
	defaultTolerance     = 0.1   // 评分切换容差，当前节点评分 ≤ 最优节点评分 + tolerance 时不切换
	defaultDegradeFactor = 1.5   // 退化因子默认值
	defaultDecayLambda   = 0.001 // 速度衰减系数，半衰期 ≈ 11.5 分钟
)

type smartOption func(*Smart)

type nodeMetrics struct {
	proxy C.Proxy
	delay uint16
	loss  float64
	speed uint64
	alive bool
}

type TestResult struct {
	At      time.Time
	Success bool
}

type NodeState struct {
	mu                  sync.Mutex
	LastObservedAt      time.Time
	Baseline            uint64
	BaselineSamples     int
	HighLatencyStreak   int
	RecentSuccessDelays []uint16
	Degraded            bool
	RecoverStreak       int
	TestResults         []TestResult
}

type Smart struct {
	*GroupBase
	selected       string
	testUrl        string
	expectedStatus string
	tolerance      float64
	disableUDP     bool
	fastNode       C.Proxy
	fastSingle     *singledo.Single[C.Proxy]

	weightDelay float64
	weightLoss  float64
	weightSpeed float64

	nodeStates xsync.Map[string, *NodeState]
}

func (s *Smart) Now() string {
	return s.fast(false).Name()
}

func (s *Smart) Set(name string) error {
	var p C.Proxy
	for _, proxy := range s.GetProxies(false) {
		if proxy.Name() == name {
			p = proxy
			break
		}
	}
	if p == nil {
		return errors.New("proxy not exist")
	}
	s.ForceSet(name)
	return nil
}

func (s *Smart) ForceSet(name string) {
	s.selected = name
	s.fastSingle.Reset()
}

func (s *Smart) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy := s.fast(true)
	c, err = proxy.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(s)
	} else {
		s.onDialFailed(proxy, err)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				s.onDialSuccess()
			} else {
				s.onDialFailed(proxy, err)
			}
		})
	}

	return c, err
}

func (s *Smart) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy := s.fast(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(s)
	} else {
		s.onDialFailed(proxy, err)
	}

	return pc, err
}

func (s *Smart) SupportUDP() bool {
	if s.disableUDP {
		return false
	}
	return s.fast(false).SupportUDP()
}

func (s *Smart) IsL3Protocol(metadata *C.Metadata) bool {
	return s.fast(false).IsL3Protocol(metadata)
}

func (s *Smart) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return s.fast(touch)
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
		"hidden":         s.Hidden(),
		"icon":           s.Icon(),
		"weight-delay":   s.weightDelay,
		"weight-loss":    s.weightLoss,
		"weight-speed":   s.weightSpeed,
		"tolerance":      s.tolerance,
	})
}

func (s *Smart) Providers() []P.ProxyProvider {
	return s.providers
}

func (s *Smart) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

func (s *Smart) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	return s.GroupBase.URLTest(ctx, s.testUrl, expectedStatus)
}

func (s *Smart) resolve(proxy C.Proxy) C.Proxy {
	// 通过 proxy.Adapter() 获取底层 adapter（因为候选节点可能是 *adapter.Proxy 包装）
	// type switch 到具体 group 类型，调用其 fast/findAliveProxy/selectedProxy 拿到 leaf
	// leaf proxy 直接返回，因为速度/延迟/丢包等物理指标只在 leaf 层有意义
	adapter := proxy.Adapter()
	switch a := adapter.(type) {
	case *URLTest:
		return a.fast(false)
	case *Fallback:
		return a.findAliveProxy(false)
	case *Selector:
		return a.selectedProxy(false)
	case *Smart:
		return a.fast(false)
	default:
		return proxy
	}
}

func (s *Smart) fast(touch bool) C.Proxy {
	elm, _, _ := s.fastSingle.Do(func() (C.Proxy, error) {
		proxies := s.GetProxies(touch)
		if len(proxies) == 0 {
			return nil, errors.New("no proxies")
		}

		if s.selected != "" {
			for _, p := range proxies {
				if !p.AliveForTestUrl(s.testUrl) {
					continue
				}
				if p.Name() == s.selected {
					s.fastNode = p
					return p, nil
				}
			}
		}

		var aliveProxies []C.Proxy
		hasData := false
		for _, p := range proxies {
			if p.AliveForTestUrl(s.testUrl) {
				aliveProxies = append(aliveProxies, p)
			}
			if p.LastDelayForTestUrl(s.testUrl) != 0xffff {
				hasData = true
			}
		}
		if len(aliveProxies) == 0 {
			chosen := proxies[rand.Intn(len(proxies))]
			s.fastNode = chosen
			return chosen, nil
		}
		if !hasData {
			chosen := aliveProxies[rand.Intn(len(aliveProxies))]
			s.fastNode = chosen
			return chosen, nil
		}

		// 收集所有候选节点指标（通过 resolve 拿到 leaf proxy 读取物理指标）
		metrics := make([]nodeMetrics, 0, len(proxies))
		for _, p := range proxies {
			resolved := s.resolve(p)
			s.ingestProbeResult(p.Name(), resolved)
			metrics = append(metrics, nodeMetrics{
				proxy: p,
				delay: resolved.LastDelayForTestUrl(s.testUrl),
				loss:  s.PacketLossRate(p.Name()),
				speed: resolved.EffectiveSpeed(),
				alive: resolved.AliveForTestUrl(s.testUrl),
			})
		}

		best := s.selectBest(metrics)
		s.fastNode = best
		return best, nil
	})
	return elm
}

func (s *Smart) ingestProbeResult(proxyName string, resolved C.Proxy) {
	extra := resolved.ExtraDelayHistories()
	state, ok := extra[s.testUrl]
	if !ok || len(state.History) == 0 {
		return
	}

	latest := state.History[len(state.History)-1]
	nodeState := s.getNodeState(proxyName)
	nodeState.mu.Lock()
	if !latest.Time.After(nodeState.LastObservedAt) {
		nodeState.mu.Unlock()
		return
	}
	nodeState.LastObservedAt = latest.Time
	nodeState.mu.Unlock()

	success := latest.Delay > 0 && state.Alive
	s.PushTestResult(proxyName, success)
	s.updateBaseline(proxyName, success, latest.Delay)
	s.updateDegraded(proxyName, success, latest.Delay)
}

func (s *Smart) selectBest(metrics []nodeMetrics) C.Proxy {
	// 1. 计算速度参考值（P90 锚定，限制在 [floor, ceiling]）
	speedRef := s.computeSpeedRef(metrics)
	var best C.Proxy
	var bestScore float64 = math.MaxFloat64
	var currentScore float64 = math.MaxFloat64

	// 2. 遍历所有存活节点，计算加权评分，选最低分
	for _, m := range metrics {
		if !m.alive {
			continue
		}
		score := s.calculateScore(m, speedRef)
		if score < bestScore {
			bestScore = score
			best = m.proxy
		}
		// 记录当前节点的评分
		if s.fastNode != nil && m.proxy == s.fastNode {
			currentScore = score
		}
	}

	// 3. 兜底：如果所有节点都不存活，选第一个
	if best == nil && len(metrics) > 0 {
		best = metrics[0].proxy
	}

	// 4. 评分容差防抖：当前节点评分 ≤ 最优节点评分 + tolerance 时不切换
	//    维度一致（都是评分），只有评分优势超过 tolerance 才切换
	if s.fastNode != nil && currentScore <= bestScore+s.tolerance {
		return s.fastNode
	}

	return best
}

func (s *Smart) computeSpeedRef(metrics []nodeMetrics) float64 {
	// 收集所有存活且有速度数据的节点
	speeds := make([]float64, 0, len(metrics))
	for _, m := range metrics {
		if m.alive && m.speed > 0 {
			speeds = append(speeds, float64(m.speed))
		}
	}
	// 样本不足 3 个时用地板值保底，避免 0/0 和慢网络 inflation
	if len(speeds) < minSpeedSamples {
		return speedRefFloor
	}
	// P90 锚定：限制在 [floor, ceiling] 防止极端值
	p90 := percentile(speeds, 0.90)
	if p90 < speedRefFloor {
		return speedRefFloor
	}
	if p90 > speedRefCeiling {
		return speedRefCeiling
	}
	return p90
}

func (s *Smart) calculateScore(m nodeMetrics, speedRef float64) float64 {
	// 延迟归一化：delay/2000ms，上限 1.0（2000ms 以上视为最差）
	normDelay := float64(m.delay) / 2000.0
	if normDelay > 1.0 {
		normDelay = 1.0
	}
	// 丢包归一化：直接使用失败率，上限 1.0
	normLoss := m.loss
	if normLoss > 1.0 {
		normLoss = 1.0
	}

	var score float64
	if m.speed == 0 {
		// 无速度数据时跳过速度项（等价于 norm_speed=1，中性值不奖不罚）
		score = s.weightDelay*normDelay + s.weightLoss*normLoss
	} else {
		// 速度归一化：speed/speedRef，上限 1.0
		normSpeed := float64(m.speed) / speedRef
		if normSpeed > 1.0 {
			normSpeed = 1.0
		}
		// 速度是正向指标，所以用 (1 - normSpeed)
		score = s.weightDelay*normDelay + s.weightLoss*normLoss + s.weightSpeed*(1.0-normSpeed)
	}

	// 退化节点加惩罚分
	if s.isDegraded(m.proxy.Name()) {
		score += degradePenalty
	}

	return score
}

func (s *Smart) getNodeState(name string) *NodeState {
	state, _ := s.nodeStates.LoadOrStoreFn(name, func() *NodeState {
		return &NodeState{
			TestResults:         make([]TestResult, 0, 20),
			RecentSuccessDelays: make([]uint16, 0, 10),
		}
	})
	return state
}

func (s *Smart) updateBaseline(proxyName string, success bool, delay uint16) {
	state := s.getNodeState(proxyName)
	state.mu.Lock()
	defer state.mu.Unlock()

	if !success {
		return
	}

	// 样本不足时，用算术平均 bootstrap 基线
	if state.BaselineSamples < baselineMinSamples {
		state.BaselineSamples++
		state.Baseline = (state.Baseline*uint64(state.BaselineSamples-1) + uint64(delay)) / uint64(state.BaselineSamples)
		state.RecentSuccessDelays = append(state.RecentSuccessDelays, delay)
		return
	}

	// 异常值忽略：延迟 > 基线×3 视为 spike，不更新基线
	// 连续 5 次高延迟说明网络环境真的变了，用中位数重校准
	if uint64(delay) > uint64(float64(state.Baseline)*spikeIgnoreFactor) {
		state.HighLatencyStreak++
		if state.HighLatencyStreak >= reseedHighStreak {
			state.Baseline = medianUint16(state.RecentSuccessDelays)
			state.HighLatencyStreak = 0
		}
		return
	}

	state.HighLatencyStreak = 0
	state.RecentSuccessDelays = append(state.RecentSuccessDelays, delay)
	if len(state.RecentSuccessDelays) > 10 {
		state.RecentSuccessDelays = state.RecentSuccessDelays[1:]
	}

	// Capped EMA：单次最多上涨 25%，防止 spike 缓慢污染基线
	capped := uint64(delay)
	maxUp := uint64(float64(state.Baseline) * baselineMaxStepUp)
	if capped > maxUp {
		capped = maxUp
	}
	state.Baseline = uint64((1.0-baselineAlpha)*float64(state.Baseline) + baselineAlpha*float64(capped))
}

func (s *Smart) updateDegraded(proxyName string, success bool, delay uint16) {
	state := s.getNodeState(proxyName)
	state.mu.Lock()
	defer state.mu.Unlock()

	// 失败立即标记退化
	if !success {
		state.Degraded = true
		state.RecoverStreak = 0
		return
	}

	// 基线未建立时，连续 2 次成功清除退化
	if state.BaselineSamples < 3 {
		if state.Degraded {
			state.RecoverStreak++
			if state.RecoverStreak >= recoverSuccesses {
				state.Degraded = false
				state.RecoverStreak = 0
			}
		}
		return
	}

	// 延迟 > 基线×degradeFactor → 标记退化
	if uint64(delay) > uint64(float64(state.Baseline)*degradeFactor) {
		state.Degraded = true
		state.RecoverStreak = 0
		return
	}

	// 滞后清除：延迟 ≤ 基线×recoverFactor 且连续 N 次成功才清除
	// recoverFactor < degradeFactor 防止抖动（hysteresis）
	if state.Degraded && uint64(delay) <= uint64(float64(state.Baseline)*recoverFactor) {
		state.RecoverStreak++
		if state.RecoverStreak >= recoverSuccesses {
			state.Degraded = false
			state.RecoverStreak = 0
		}
	} else {
		state.RecoverStreak = 0
	}
}

func (s *Smart) markDegraded(proxyName string) {
	state := s.getNodeState(proxyName)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.Degraded = true
	state.RecoverStreak = 0
}

func (s *Smart) isDegraded(proxyName string) bool {
	state, ok := s.nodeStates.Load(proxyName)
	if !ok {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.Degraded
}

func (s *Smart) PushTestResult(proxyName string, success bool) {
	state := s.getNodeState(proxyName)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.TestResults = append(state.TestResults, TestResult{At: time.Now(), Success: success})
	if len(state.TestResults) > 20 {
		state.TestResults = state.TestResults[1:]
	}
}

func (s *Smart) PacketLossRate(proxyName string) float64 {
	state, ok := s.nodeStates.Load(proxyName)
	if !ok {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	if len(state.TestResults) == 0 {
		return 0
	}

	// 时间上限：interval=300s → 30min，interval=30s → 10min
	// 防止 interval 过大时丢包率反映太久远的状态
	maxAge := 30 * time.Minute
	interval := 300
	if interval > 0 {
		age := time.Duration(6*interval) * time.Second
		if age < 10*time.Minute {
			age = 10 * time.Minute
		}
		if age > 30*time.Minute {
			age = 30 * time.Minute
		}
		maxAge = age
	}

	// 倒序遍历，最多取 20 个样本，超过 maxAge 的丢弃
	now := time.Now()
	n, fails := 0, 0
	for i := len(state.TestResults) - 1; i >= 0 && n < 20; i-- {
		if now.Sub(state.TestResults[i].At) > maxAge {
			break
		}
		n++
		if !state.TestResults[i].Success {
			fails++
		}
	}

	// 样本不足 3 个不惩罚
	if n < 3 {
		return 0
	}
	// 置信度门控：3-5 个样本部分权重，5+ 个全权重
	confidence := float64(n) / 5.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	return float64(fails) / float64(n) * confidence
}

func (s *Smart) onDialFailed(proxy C.Proxy, err error) {
	// 自修复组（URLTest/Fallback/LoadBalance/Smart）内部会切换 leaf，Smart 只需清除缓存重新评估
	// 非自修复组（Selector/Leaf）无自修复能力，Smart 需要主动标记退化并避开
	if isSelfHealingGroup(proxy.Type()) {
		s.fastSingle.Reset()
	} else {
		s.markDegraded(proxy.Name())
		s.fastSingle.Reset()
	}
}

func (s *Smart) onDialSuccess() {
	s.GroupBase.onDialSuccess()
}

func isSelfHealingGroup(t C.AdapterType) bool {
	return t == C.URLTest || t == C.Fallback || t == C.LoadBalance || t == C.Smart
}

func (s *Smart) EffectiveSpeed() uint64 {
	return s.fast(false).EffectiveSpeed()
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	index := p * float64(len(sorted)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))
	if lower == upper {
		return sorted[lower]
	}
	weight := index - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

func medianUint16(values []uint16) uint64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]uint16, len(values))
	copy(sorted, values)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (uint64(sorted[mid-1]) + uint64(sorted[mid])) / 2
	}
	return uint64(sorted[mid])
}

func NewSmart(option *GroupCommonOption, providers []P.ProxyProvider, options ...smartOption) (*Smart, error) {
	// 递归检查所有子节点（包括嵌套组内部），不允许 LoadBalance 作为子节点
	if err := checkNoLoadBalance(providers); err != nil {
		return nil, err
	}

	smart := &Smart{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Smart,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			Providers:      providers,
		}),
		fastSingle:     singledo.NewSingle[C.Proxy](10 * time.Second),
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		weightDelay:    defaultWeightDelay,
		weightLoss:     defaultWeightLoss,
		weightSpeed:    defaultWeightSpeed,
		tolerance:      defaultTolerance,
	}

	for _, opt := range options {
		opt(smart)
	}

	return smart, nil
}

func checkNoLoadBalance(providers []P.ProxyProvider) error {
	for _, pd := range providers {
		for _, p := range pd.Proxies() {
			if err := checkNoLoadBalanceRecursive(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkNoLoadBalanceRecursive(p C.Proxy) error {
	if p.Type() == C.LoadBalance {
		return errors.New("smart group does not support LoadBalance as child: " + p.Name())
	}
	if adapter := p.Adapter(); adapter != nil {
		switch a := adapter.(type) {
		case *URLTest:
			for _, child := range a.GetProxies(false) {
				if err := checkNoLoadBalanceRecursive(child); err != nil {
					return err
				}
			}
		case *Fallback:
			for _, child := range a.GetProxies(false) {
				if err := checkNoLoadBalanceRecursive(child); err != nil {
					return err
				}
			}
		case *Selector:
			for _, child := range a.GetProxies(false) {
				if err := checkNoLoadBalanceRecursive(child); err != nil {
					return err
				}
			}
		case *Smart:
			for _, child := range a.GetProxies(false) {
				if err := checkNoLoadBalanceRecursive(child); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
