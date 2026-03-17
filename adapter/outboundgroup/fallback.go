package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

type Fallback struct {
	*GroupBase
	stateMux              sync.RWMutex
	disableUDP            bool
	testUrl               string
	selected              string
	expectedStatus        string
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
}

func (f *Fallback) Now() string {
	proxy := f.findAliveProxy(false)
	return proxy.Name()
}

// DialContext implements C.ProxyAdapter
func (f *Fallback) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	proxy := f.findAliveProxy(true)
	c, err := proxy.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(f)
	} else {
		f.onDialFailed(proxy.Type(), err, f.healthCheck)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				f.onDialSuccess()
			} else {
				f.onDialFailed(proxy.Type(), err, f.healthCheck)
			}
		})
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (f *Fallback) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy := f.findAliveProxy(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(f)
	}

	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (f *Fallback) SupportUDP() bool {
	if f.disableUDP {
		return false
	}

	proxy := f.findAliveProxy(false)
	return proxy.SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (f *Fallback) IsL3Protocol(metadata *C.Metadata) bool {
	return f.findAliveProxy(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (f *Fallback) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range f.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":                            f.Type().String(),
		"now":                             f.Now(),
		"all":                             all,
		"testUrl":                         f.testUrl,
		"expectedStatus":                  f.expectedStatus,
		"fixed":                           f.getSelected(),
		"persistentPin":                   f.persistentPin,
		"pinUnhealthyLogInterval":         int(f.pinWarnInterval / time.Second),
		"persistentPinAutoUnfixThreshold": f.pinAutoUnfixThreshold,
		"hidden":                          f.Hidden,
		"icon":                            f.Icon,
	})
}

// Unwrap implements C.ProxyAdapter
func (f *Fallback) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxy := f.findAliveProxy(touch)
	return proxy
}

func (f *Fallback) findAliveProxy(touch bool) C.Proxy {
	proxies := f.GetProxies(touch)
	selected := f.getSelected()

	if len(selected) != 0 {
		foundSelected := false
		for _, proxy := range proxies {
			if proxy.Name() != selected {
				continue
			}
			foundSelected = true
			if f.persistentPin {
				if f.observePersistentPinnedResult(selected, proxy, proxies) {
					break
				}
				if !proxy.AliveForTestUrl(f.testUrl) {
					f.warnPersistentPinnedProxy(selected, "unhealthy")
				}
				return proxy
			}
			if proxy.AliveForTestUrl(f.testUrl) {
				return proxy
			}
			f.clearSelectedIf(selected)
			break
		}
		if f.persistentPin && !foundSelected {
			f.clearSelectedIf(selected)
			f.warnPersistentPinnedProxy(selected, "missing")
		}
	}

	for _, proxy := range proxies {
		if proxy.AliveForTestUrl(f.testUrl) {
			return proxy
		}
	}

	return proxies[0]
}

func (f *Fallback) Set(name string) error {
	var p C.Proxy
	for _, proxy := range f.GetProxies(false) {
		if proxy.Name() == name {
			p = proxy
			break
		}
	}

	if p == nil {
		return errors.New("proxy not exist")
	}

	f.setSelected(name)
	if !p.AliveForTestUrl(f.testUrl) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(5000))
		defer cancel()
		expectedStatus, _ := utils.NewUnsignedRanges[uint16](f.expectedStatus)
		_, _ = p.URLTest(ctx, f.testUrl, expectedStatus)
	}

	return nil
}

func (f *Fallback) ForceSet(name string) {
	f.setSelected(name)
}

func (f *Fallback) PersistentPin() bool {
	return f.persistentPin
}

func (f *Fallback) getSelected() string {
	f.stateMux.RLock()
	defer f.stateMux.RUnlock()

	return f.selected
}

func (f *Fallback) setSelected(name string) {
	f.stateMux.Lock()
	f.selected = name
	f.resetPersistentPinStateLocked()
	f.stateMux.Unlock()
}

func (f *Fallback) clearSelectedIf(selected string) {
	f.stateMux.Lock()
	if f.selected == selected {
		f.selected = ""
		f.resetPersistentPinStateLocked()
	}
	f.stateMux.Unlock()
}

func (f *Fallback) resetPersistentPinStateLocked() {
	f.pinAutoUnfixCount = 0
	f.pinAutoUnfixLastTest = time.Time{}
	f.lastPinWarnAt = time.Time{}
	f.lastPinWarnFor = ""
	f.lastPinWarnMsg = ""
}

func (f *Fallback) observePersistentPinnedResult(selected string, pinned C.Proxy, proxies []C.Proxy) bool {
	history, ok := proxyTestHistory(pinned, f.testUrl)
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
			if proxy.AliveForTestUrl(f.testUrl) {
				hasOtherAlive = true
				break
			}
		}
	}

	threshold := f.pinAutoUnfixThreshold
	if threshold <= 0 {
		threshold = defaultPersistentPinAutoUnfixThreshold
	}

	autoUnfixed := false
	reachedCount := 0
	resetByHealthy := false
	resetReason := ""
	resetFrom := 0

	f.stateMux.Lock()
	if f.selected != selected || !lastTestAt.After(f.pinAutoUnfixLastTest) {
		f.stateMux.Unlock()
		return false
	}

	for _, record := range history {
		if record.Time.After(f.pinAutoUnfixLastTest) && record.Delay != 0 {
			resetByHealthy = true
			break
		}
	}
	f.pinAutoUnfixLastTest = lastTestAt
	if resetByHealthy {
		if f.pinAutoUnfixCount > 0 {
			resetReason = "pinned proxy has successful test records"
			resetFrom = f.pinAutoUnfixCount
		}
		f.pinAutoUnfixCount = 0
	}
	if lastHealthy {
		if f.pinAutoUnfixCount > 0 {
			resetReason = "pinned proxy recovered"
			resetFrom = f.pinAutoUnfixCount
		}
		f.pinAutoUnfixCount = 0
	} else if hasOtherAlive {
		f.pinAutoUnfixCount++
		if f.pinAutoUnfixCount >= threshold {
			reachedCount = f.pinAutoUnfixCount
			f.selected = ""
			f.resetPersistentPinStateLocked()
			autoUnfixed = true
		}
	} else {
		if f.pinAutoUnfixCount > 0 {
			resetReason = "no alternative alive proxies in group"
			resetFrom = f.pinAutoUnfixCount
		}
		f.pinAutoUnfixCount = 0
	}
	f.stateMux.Unlock()

	if resetReason != "" {
		log.Warnln("group [%s] reset persistent pin auto-unfix counter for proxy [%s] from %d to 0 (%s)", f.Name(), selected, resetFrom, resetReason)
	}
	if autoUnfixed {
		log.Warnln("group [%s] auto-unfixed persistent pin on proxy [%s] after %d consecutive unhealthy checks with alternative alive proxies", f.Name(), selected, reachedCount)
	}
	return autoUnfixed
}

func (f *Fallback) warnPersistentPinnedProxy(selected, reason string) {
	interval := f.pinWarnInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	shouldLog := false
	counter := 0
	threshold := f.pinAutoUnfixThreshold
	if threshold <= 0 {
		threshold = defaultPersistentPinAutoUnfixThreshold
	}
	f.stateMux.Lock()
	now := time.Now()
	if f.lastPinWarnFor != selected || f.lastPinWarnMsg != reason || now.Sub(f.lastPinWarnAt) >= interval {
		f.lastPinWarnFor = selected
		f.lastPinWarnMsg = reason
		f.lastPinWarnAt = now
		shouldLog = true
	}
	counter = f.pinAutoUnfixCount
	f.stateMux.Unlock()
	if !shouldLog {
		return
	}

	switch reason {
	case "missing":
		log.Warnln("group [%s] cleared persistent pin because proxy [%s] no longer exists in current members", f.Name(), selected)
	default:
		log.Warnln("group [%s] keeps persistent pin on unhealthy proxy [%s]; traffic remains pinned until manual unfix (auto-unfix counter %d/%d)", f.Name(), selected, counter, threshold)
	}
}

func (f *Fallback) Providers() []P.ProxyProvider {
	return f.providers
}

func (f *Fallback) Proxies() []C.Proxy {
	return f.GetProxies(false)
}

func NewFallback(option *GroupCommonOption, providers []P.ProxyProvider) *Fallback {
	pinWarnInterval := 10 * time.Second
	if option.PinUnhealthyLogInterval > 0 {
		pinWarnInterval = time.Duration(option.PinUnhealthyLogInterval) * time.Second
	}
	pinAutoUnfixThreshold := defaultPersistentPinAutoUnfixThreshold
	if option.PersistentPinAutoUnfixThreshold > 0 {
		pinAutoUnfixThreshold = option.PersistentPinAutoUnfixThreshold
	}

	return &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Fallback,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			Providers:      providers,
		}),
		disableUDP:            option.DisableUDP,
		testUrl:               option.URL,
		expectedStatus:        option.ExpectedStatus,
		persistentPin:         option.PersistentPin,
		pinWarnInterval:       pinWarnInterval,
		pinAutoUnfixThreshold: pinAutoUnfixThreshold,
		Hidden:                option.Hidden,
		Icon:                  option.Icon,
	}
}
