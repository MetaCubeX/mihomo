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
)

type urlTestOption func(*URLTest)

func urlTestWithTolerance(tolerance uint16) urlTestOption {
	return func(u *URLTest) {
		u.tolerance = tolerance
	}
}

type URLTest struct {
	*GroupBase
	stateMux       sync.RWMutex
	selected       string
	testUrl        string
	expectedStatus string
	tolerance      uint16
	disableUDP     bool
	Hidden         bool
	Icon           string
	fastNode       C.Proxy
	fastSingle     *singledo.Single[C.Proxy]
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
	u.stateMux.Lock()
	u.selected = name
	u.stateMux.Unlock()
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
			for _, proxy := range proxies {
				if !proxy.AliveForTestUrl(u.testUrl) {
					continue
				}
				if proxy.Name() == selected {
					u.setFastNode(proxy)
					return proxy, nil
				}
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
		"type":           u.Type().String(),
		"now":            u.Now(),
		"all":            all,
		"testUrl":        u.testUrl,
		"expectedStatus": u.expectedStatus,
		"fixed":          u.getSelected(),
		"hidden":         u.Hidden,
		"icon":           u.Icon,
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
		fastSingle:     singledo.NewSingle[C.Proxy](time.Second * 10),
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		Hidden:         option.Hidden,
		Icon:           option.Icon,
	}

	for _, option := range options {
		option(urlTest)
	}

	return urlTest
}
