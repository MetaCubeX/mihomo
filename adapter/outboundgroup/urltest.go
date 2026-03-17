package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

type urlTestOption func(*URLTest)

func urlTestWithTolerance(tolerance uint16) urlTestOption {
	return func(u *URLTest) {
		u.tolerance = tolerance
	}
}

type URLTest struct {
	*GroupBase
	stateMux              sync.RWMutex
	selected              string
	testUrl               string
	expectedStatus        string
	tolerance             uint16
	disableUDP            bool
	persistentPin         bool
	pinWarnInterval       time.Duration
	pinAutoUnfixThreshold int
	pinAutoUnfixCount     int
	pinAutoUnfixLastTest  time.Time
	lastPinWarnAt         time.Time
	lastPinWarnFor        string
	lastPinWarnMsg        string
	Hidden                bool
	Icon                  string
	fastNode              C.Proxy
	fastSingle            *singledo.Single[C.Proxy]
}

func (u *URLTest) Now() string {
	return u.fast(false).Name()
}

func (u *URLTest) Set(name string) error {
	var p C.Proxy
	for _, proxy := range u.GetProxies(false) {
		if proxy.Name() == name {
			p = proxy
			break
		}
	}
	if p == nil {
		return errors.New("proxy not exist")
	}
	u.ForceSet(name)
	return nil
}

func (u *URLTest) ForceSet(name string) {
	u.setSelected(name)
	u.fastSingle.Reset()
}

// DialContext implements C.ProxyAdapter
func (u *URLTest) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy := u.fast(true)
	c, err = proxy.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(u)
	} else {
		u.onDialFailed(proxy.Type(), err, u.healthCheck)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				u.onDialSuccess()
			} else {
				u.onDialFailed(proxy.Type(), err, u.healthCheck)
			}
		})
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (u *URLTest) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy := u.fast(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(u)
	} else {
		u.onDialFailed(proxy.Type(), err, u.healthCheck)
	}

	return pc, err
}

// Unwrap implements C.ProxyAdapter
func (u *URLTest) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return u.fast(touch)
}

func (u *URLTest) healthCheck() {
	u.fastSingle.Reset()
	u.GroupBase.healthCheck()
	u.fastSingle.Reset()
}

func (u *URLTest) fast(touch bool) C.Proxy {
	elm, _, shared := u.fastSingle.Do(func() (C.Proxy, error) {
		proxies := u.GetProxies(touch)
		selected, fastNode := u.snapshotState()

		if selected != "" {
			foundSelected := false
			for _, proxy := range proxies {
				if proxy.Name() == selected {
					foundSelected = true
					if u.persistentPin {
						if u.observePersistentPinnedResult(selected, proxy, proxies) {
							break
						}
						if !proxy.AliveForTestUrl(u.testUrl) {
							u.warnPersistentPinnedProxy(selected, "unhealthy")
						}
						u.setFastNode(proxy)
						return proxy, nil
					}
					if !proxy.AliveForTestUrl(u.testUrl) {
						continue
					}
					u.setFastNode(proxy)
					return proxy, nil
				}
			}
			if u.persistentPin && !foundSelected {
				u.clearSelectedIf(selected)
				u.warnPersistentPinnedProxy(selected, "missing")
			}
		}

		var (
			fast         C.Proxy
			fastDelay    uint16
			hasAliveFast bool
			fastNotExist = true
		)

		for _, proxy := range proxies {
			if fastNode != nil && proxy.Name() == fastNode.Name() {
				fastNotExist = false
			}

			if !proxy.AliveForTestUrl(u.testUrl) {
				continue
			}

			delay := proxy.LastDelayForTestUrl(u.testUrl)
			if !hasAliveFast || delay < fastDelay {
				fast = proxy
				fastDelay = delay
				hasAliveFast = true
			}
		}

		// Do not fall back to timeout nodes when at least one alive node exists.
		if hasAliveFast {
			// tolerance
			if fastNode == nil || fastNotExist || !fastNode.AliveForTestUrl(u.testUrl) || fastNode.LastDelayForTestUrl(u.testUrl) > fastDelay+u.tolerance {
				fastNode = fast
			}
		} else if fastNode == nil || fastNotExist || !fastNode.AliveForTestUrl(u.testUrl) {
			fastNode = proxies[0]
		}

		u.setFastNode(fastNode)
		return fastNode, nil
	})
	if shared && touch { // a shared fastSingle.Do() may cause providers untouched, so we touch them again
		u.Touch()
	}

	return elm
}

func (u *URLTest) snapshotState() (string, C.Proxy) {
	u.stateMux.RLock()
	defer u.stateMux.RUnlock()

	return u.selected, u.fastNode
}

func (u *URLTest) getSelected() string {
	u.stateMux.RLock()
	defer u.stateMux.RUnlock()

	return u.selected
}

func (u *URLTest) setFastNode(proxy C.Proxy) {
	u.stateMux.Lock()
	u.fastNode = proxy
	u.stateMux.Unlock()
}

func (u *URLTest) setSelected(name string) {
	u.stateMux.Lock()
	u.selected = name
	u.resetPersistentPinStateLocked()
	u.stateMux.Unlock()
}

func (u *URLTest) clearSelectedIf(selected string) {
	u.stateMux.Lock()
	if u.selected == selected {
		u.selected = ""
		u.resetPersistentPinStateLocked()
	}
	u.stateMux.Unlock()
}

func (u *URLTest) PersistentPin() bool {
	return u.persistentPin
}

func (u *URLTest) warnPersistentPinnedProxy(selected, reason string) {
	interval := u.pinWarnInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	shouldLog := false
	counter := 0
	threshold := u.pinAutoUnfixThreshold
	if threshold <= 0 {
		threshold = defaultPersistentPinAutoUnfixThreshold
	}
	u.stateMux.Lock()
	now := time.Now()
	if u.lastPinWarnFor != selected || u.lastPinWarnMsg != reason || now.Sub(u.lastPinWarnAt) >= interval {
		u.lastPinWarnFor = selected
		u.lastPinWarnMsg = reason
		u.lastPinWarnAt = now
		shouldLog = true
	}
	counter = u.pinAutoUnfixCount
	u.stateMux.Unlock()
	if !shouldLog {
		return
	}

	switch reason {
	case "missing":
		log.Warnln("group [%s] cleared persistent pin because proxy [%s] no longer exists in current members", u.Name(), selected)
	default:
		log.Warnln("group [%s] keeps persistent pin on unhealthy proxy [%s]; traffic remains pinned until manual unfix (auto-unfix counter %d/%d)", u.Name(), selected, counter, threshold)
	}
}

func (u *URLTest) resetPersistentPinStateLocked() {
	u.pinAutoUnfixCount = 0
	u.pinAutoUnfixLastTest = time.Time{}
	u.lastPinWarnAt = time.Time{}
	u.lastPinWarnFor = ""
	u.lastPinWarnMsg = ""
}

func (u *URLTest) observePersistentPinnedResult(selected string, pinned C.Proxy, proxies []C.Proxy) bool {
	history, ok := proxyTestHistory(pinned, u.testUrl)
	if !ok {
		return false
	}
	lastRecord := history[len(history)-1]
	lastTestAt := lastRecord.Time
	lastHealthy := lastRecord.Delay != 0
	hasOtherAlive := false
	if !lastHealthy {
		for _, proxy := range proxies {
			if proxy.Name() == selected {
				continue
			}
			if proxy.AliveForTestUrl(u.testUrl) {
				hasOtherAlive = true
				break
			}
		}
	}

	threshold := u.pinAutoUnfixThreshold
	if threshold <= 0 {
		threshold = defaultPersistentPinAutoUnfixThreshold
	}

	autoUnfixed := false
	reachedCount := 0
	resetByHealthy := false
	resetReason := ""
	resetFrom := 0

	u.stateMux.Lock()
	if u.selected != selected || !lastTestAt.After(u.pinAutoUnfixLastTest) {
		u.stateMux.Unlock()
		return false
	}

	for _, record := range history {
		if record.Time.After(u.pinAutoUnfixLastTest) && record.Delay != 0 {
			resetByHealthy = true
			break
		}
	}
	u.pinAutoUnfixLastTest = lastTestAt
	if resetByHealthy {
		if u.pinAutoUnfixCount > 0 {
			resetReason = "pinned proxy has successful test records"
			resetFrom = u.pinAutoUnfixCount
		}
		u.pinAutoUnfixCount = 0
	}
	if lastHealthy {
		if u.pinAutoUnfixCount > 0 {
			resetReason = "pinned proxy recovered"
			resetFrom = u.pinAutoUnfixCount
		}
		u.pinAutoUnfixCount = 0
	} else if hasOtherAlive {
		u.pinAutoUnfixCount++
		if u.pinAutoUnfixCount >= threshold {
			reachedCount = u.pinAutoUnfixCount
			u.selected = ""
			u.resetPersistentPinStateLocked()
			autoUnfixed = true
		}
	} else {
		if u.pinAutoUnfixCount > 0 {
			resetReason = "no alternative alive proxies in group"
			resetFrom = u.pinAutoUnfixCount
		}
		u.pinAutoUnfixCount = 0
	}
	u.stateMux.Unlock()

	if resetReason != "" {
		log.Warnln("group [%s] reset persistent pin auto-unfix counter for proxy [%s] from %d to 0 (%s)", u.Name(), selected, resetFrom, resetReason)
	}
	if autoUnfixed {
		log.Warnln("group [%s] auto-unfixed persistent pin on proxy [%s] after %d consecutive unhealthy checks with alternative alive proxies", u.Name(), selected, reachedCount)
	}
	return autoUnfixed
}

// SupportUDP implements C.ProxyAdapter
func (u *URLTest) SupportUDP() bool {
	if u.disableUDP {
		return false
	}
	return u.fast(false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (u *URLTest) IsL3Protocol(metadata *C.Metadata) bool {
	return u.fast(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (u *URLTest) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range u.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":                            u.Type().String(),
		"now":                             u.Now(),
		"all":                             all,
		"testUrl":                         u.testUrl,
		"expectedStatus":                  u.expectedStatus,
		"fixed":                           u.getSelected(),
		"persistentPin":                   u.persistentPin,
		"pinUnhealthyLogInterval":         int(u.pinWarnInterval / time.Second),
		"persistentPinAutoUnfixThreshold": u.pinAutoUnfixThreshold,
		"hidden":                          u.Hidden,
		"icon":                            u.Icon,
	})
}

func (u *URLTest) Providers() []P.ProxyProvider {
	return u.providers
}

func (u *URLTest) Proxies() []C.Proxy {
	return u.GetProxies(false)
}

func (u *URLTest) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	delays, err := u.GroupBase.URLTest(ctx, u.testUrl, expectedStatus)
	// URL tests update alive/delay history; reset cache so next routing picks fresh best node.
	u.fastSingle.Reset()
	_ = u.fast(false)
	return delays, err
}

func parseURLTestOption(config map[string]any) []urlTestOption {
	opts := []urlTestOption{}

	// tolerance
	if elm, ok := config["tolerance"]; ok {
		if tolerance, ok := elm.(int); ok {
			opts = append(opts, urlTestWithTolerance(uint16(tolerance)))
		}
	}

	return opts
}

func NewURLTest(option *GroupCommonOption, providers []P.ProxyProvider, options ...urlTestOption) *URLTest {
	pinWarnInterval := 10 * time.Second
	if option.PinUnhealthyLogInterval > 0 {
		pinWarnInterval = time.Duration(option.PinUnhealthyLogInterval) * time.Second
	}
	pinAutoUnfixThreshold := defaultPersistentPinAutoUnfixThreshold
	if option.PersistentPinAutoUnfixThreshold > 0 {
		pinAutoUnfixThreshold = option.PersistentPinAutoUnfixThreshold
	}

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.URLTest,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			Providers:      providers,
		}),
		fastSingle:            singledo.NewSingle[C.Proxy](time.Second * 10),
		disableUDP:            option.DisableUDP,
		testUrl:               option.URL,
		expectedStatus:        option.ExpectedStatus,
		persistentPin:         option.PersistentPin,
		pinWarnInterval:       pinWarnInterval,
		pinAutoUnfixThreshold: pinAutoUnfixThreshold,
		Hidden:                option.Hidden,
		Icon:                  option.Icon,
	}

	for _, option := range options {
		option(urlTest)
	}

	return urlTest
}
