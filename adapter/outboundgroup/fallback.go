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

type Fallback struct {
	*outbound.Base
	disableUDP  bool
	filter      string
	single      *singledo.Single
	providers   []provider.ProxyProvider
	failedTimes *atomic.Int32
	failedTime  *atomic.Int64
}

func (f *Fallback) Now() string {
	proxy := f.findAliveProxy(false)
	return proxy.Name()
}

// DialContext implements C.ProxyAdapter
func (f *Fallback) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	proxy := f.findAliveProxy(true)
	c, err := proxy.DialContext(ctx, metadata, f.Base.DialOptions(opts...)...)
	if err == nil {
		c.AppendToChains(f)
		f.failedTimes.Store(-1)
		f.failedTime.Store(-1)
	} else {
		f.onDialFailed()
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (f *Fallback) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	proxy := f.findAliveProxy(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata, f.Base.DialOptions(opts...)...)
	if err == nil {
		pc.AppendToChains(f)
		f.failedTimes.Store(-1)
		f.failedTime.Store(-1)
	} else {
		f.onDialFailed()
	}

	return pc, err
}

func (f *Fallback) onDialFailed() {
	if f.failedTime.Load() == -1 {
		log.Warnln("%s first failed", f.Name())
		now := time.Now().UnixMilli()
		f.failedTime.Store(now)
		f.failedTimes.Store(1)
	} else {
		if f.failedTime.Load()-time.Now().UnixMilli() > 5*time.Second.Milliseconds() {
			f.failedTimes.Store(-1)
			f.failedTime.Store(-1)
		} else {
			failedCount := f.failedTimes.Inc()
			log.Warnln("%s failed count: %d", f.Name(), failedCount)
			if failedCount >= 5 {
				log.Warnln("because %s failed multiple times, active health check", f.Name())
				for _, proxyProvider := range f.providers {
					go proxyProvider.HealthCheck()
				}

				f.failedTimes.Store(-1)
				f.failedTime.Store(-1)
			}
		}
	}
}

// SupportUDP implements C.ProxyAdapter
func (f *Fallback) SupportUDP() bool {
	if f.disableUDP {
		return false
	}

	proxy := f.findAliveProxy(false)
	return proxy.SupportUDP()
}

// MarshalJSON implements C.ProxyAdapter
func (f *Fallback) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range f.proxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": f.Type().String(),
		"now":  f.Now(),
		"all":  all,
	})
}

// Unwrap implements C.ProxyAdapter
func (f *Fallback) Unwrap(metadata *C.Metadata) C.Proxy {
	proxy := f.findAliveProxy(true)
	return proxy
}

func (f *Fallback) proxies(touch bool) []C.Proxy {
	elm, _, _ := f.single.Do(func() (any, error) {
		return getProvidersProxies(f.providers, touch), nil
	})

	return elm.([]C.Proxy)
}

func (f *Fallback) findAliveProxy(touch bool) C.Proxy {
	proxies := f.proxies(touch)
	for _, proxy := range proxies {
		if proxy.Alive() {
			return proxy
		}
	}

	return proxies[0]
}

func NewFallback(option *GroupCommonOption, providers []provider.ProxyProvider) *Fallback {
	return &Fallback{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.Fallback,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
		}),
		single:      singledo.NewSingle(defaultGetProxiesDuration),
		providers:   providers,
		disableUDP:  option.DisableUDP,
		filter:      option.Filter,
		failedTimes: atomic.NewInt32(-1),
		failedTime:  atomic.NewInt64(-1),
	}
}
