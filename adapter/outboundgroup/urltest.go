package outboundgroup

import (
	"context"
	"encoding/json"
	"github.com/Dreamacro/clash/log"
	"go.uber.org/atomic"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/singledo"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type urlTestOption func(*URLTest)

func urlTestWithTolerance(tolerance uint16) urlTestOption {
	return func(u *URLTest) {
		u.tolerance = tolerance
	}
}

type URLTest struct {
	*outbound.Base
	tolerance   uint16
	disableUDP  bool
	fastNode    C.Proxy
	filter      string
	single      *singledo.Single
	fastSingle  *singledo.Single
	providers   []provider.ProxyProvider
	failedTimes *atomic.Int32
	failedTime  *atomic.Int64
}

func (u *URLTest) IsProxyGroup() bool {
	return true
}

func (u *URLTest) Now() string {
	return u.fast(false).Name()
}

// DialContext implements C.ProxyAdapter
func (u *URLTest) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (c C.Conn, err error) {
	c, err = u.fast(true).DialContext(ctx, metadata, u.Base.DialOptions(opts...)...)
	if err == nil {
		c.AppendToChains(u)
		u.failedTimes.Store(-1)
		u.failedTime.Store(-1)
	} else {
		u.onDialFailed()
	}
	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (u *URLTest) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := u.fast(true).ListenPacketContext(ctx, metadata, u.Base.DialOptions(opts...)...)
	if err == nil {
		pc.AppendToChains(u)
		u.failedTimes.Store(-1)
		u.failedTime.Store(-1)
	} else {
		u.onDialFailed()
	}
	return pc, err
}

// Unwrap implements C.ProxyAdapter
func (u *URLTest) Unwrap(*C.Metadata) C.Proxy {
	return u.fast(true)
}

func (u *URLTest) proxies(touch bool) []C.Proxy {
	elm, _, _ := u.single.Do(func() (any, error) {
		return getProvidersProxies(u.providers, touch, u.filter), nil
	})

	return elm.([]C.Proxy)
}

func (u *URLTest) fast(touch bool) C.Proxy {
	elm, _, _ := u.fastSingle.Do(func() (any, error) {
		proxies := u.proxies(touch)
		fast := proxies[0]
		min := fast.LastDelay()
		fastNotExist := true

		for _, proxy := range proxies[1:] {
			if u.fastNode != nil && proxy.Name() == u.fastNode.Name() {
				fastNotExist = false
			}

			if !proxy.Alive() {
				continue
			}

			delay := proxy.LastDelay()
			if delay < min {
				fast = proxy
				min = delay
			}
		}

		// tolerance
		if u.fastNode == nil || fastNotExist || !u.fastNode.Alive() || u.fastNode.LastDelay() > fast.LastDelay()+u.tolerance {
			u.fastNode = fast
		}

		return u.fastNode, nil
	})

	return elm.(C.Proxy)
}

// SupportUDP implements C.ProxyAdapter
func (u *URLTest) SupportUDP() bool {
	if u.disableUDP {
		return false
	}

	return u.fast(false).SupportUDP()
}

// MarshalJSON implements C.ProxyAdapter
func (u *URLTest) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range u.proxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": u.Type().String(),
		"now":  u.Now(),
		"all":  all,
	})
}

func (u *URLTest) onDialFailed() {
	if u.failedTime.Load() == -1 {
		log.Warnln("%s first failed", u.Name())
		now := time.Now().UnixMilli()
		u.failedTime.Store(now)
		u.failedTimes.Store(1)
	} else {
		if u.failedTime.Load()-time.Now().UnixMilli() > 5*1000 {
			u.failedTimes.Store(-1)
			u.failedTime.Store(-1)
		} else {
			failedCount := u.failedTimes.Inc()
			log.Warnln("%s failed count: %d", u.Name(), failedCount)
			if failedCount >= 5 {
				log.Warnln("because %s failed multiple times, active health check", u.Name())
				for _, proxyProvider := range u.providers {
					go proxyProvider.HealthCheck()
				}

				u.failedTimes.Store(-1)
				u.failedTime.Store(-1)
			}
		}
	}
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

func NewURLTest(option *GroupCommonOption, providers []provider.ProxyProvider, options ...urlTestOption) *URLTest {
	urlTest := &URLTest{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.URLTest,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
		}),
		single:      singledo.NewSingle(defaultGetProxiesDuration),
		fastSingle:  singledo.NewSingle(time.Second * 10),
		providers:   providers,
		disableUDP:  option.DisableUDP,
		filter:      option.Filter,
		failedTimes: atomic.NewInt32(-1),
		failedTime:  atomic.NewInt64(-1),
	}

	for _, option := range options {
		option(urlTest)
	}

	return urlTest
}
