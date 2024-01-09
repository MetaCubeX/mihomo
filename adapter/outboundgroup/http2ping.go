package outboundgroup

import (
	"context"
	"encoding/json"
	"fmt"
	_ "net/http/pprof"
	"net/url"
	"reflect"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup/http2ping"
	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

type HTTP2Ping struct {
	*GroupBase
	g             http2ping.PingerGroup
	cachedProxies []C.Proxy
}

func (hp *HTTP2Ping) Now() string {
	proxy := hp.getBestProxy()
	return proxy.Name()
}

// DialContext implements C.ProxyAdapter
func (hp *HTTP2Ping) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	start := time.Now()
	proxy := hp.getBestProxy()
	if proxy == nil {
		log.Warnln("[htt2ping] no proxy available, dial direct to %v", metadata)
		direct := outbound.NewDirect()
		return direct.DialContext(ctx, metadata, hp.Base.DialOptions(opts...)...)
	}
	if cost := time.Since(start).Milliseconds(); cost > 0 {
		log.Warnln("[htt2ping] getBestProxy took %d ms to %v", cost, metadata)
	}

	c, err := proxy.DialContext(ctx, metadata, hp.Base.DialOptions(opts...)...)
	if err == nil {
		c.AppendToChains(hp)
	} else {
		hp.onDialFailed(proxy.Type(), err)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				hp.onDialSuccess()
			} else {
				hp.onDialFailed(proxy.Type(), err)
			}
		})
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (hp *HTTP2Ping) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	proxy := hp.getBestProxy()
	pc, err := proxy.ListenPacketContext(ctx, metadata, hp.Base.DialOptions(opts...)...)
	if err == nil {
		pc.AppendToChains(hp)
	}

	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (hp *HTTP2Ping) SupportUDP() bool {
	proxy := hp.getBestProxy()
	return proxy.SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (hp *HTTP2Ping) IsL3Protocol(metadata *C.Metadata) bool {
	return hp.getBestProxy().IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (hp *HTTP2Ping) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range hp.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": hp.Type().String(),
		"now":  hp.Now(),
		"all":  all,
	})
}

// Unwrap implements C.ProxyAdapter
func (hp *HTTP2Ping) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxy := hp.getBestProxy()
	return proxy
}

func (hp *HTTP2Ping) Set(name string) error {
	return fmt.Errorf("not implemented")
}

func (hp *HTTP2Ping) ForceSet(name string) {
	log.Warnln("not implemented")
}

func (hp *HTTP2Ping) getBestProxy() C.Proxy {
	return hp.g.GetMinRttProxy(context.TODO())
}

// poll for `ProxyProvider` proxies initilization and updates
func (hp *HTTP2Ping) pollForProviderProxiesUpdate(providers []provider.ProxyProvider) {
	// TODO: use dynamic fallback timer
	ticker := time.NewTicker(time.Second)
	for range ticker.C {
		proxies := hp.GetProxies(true)
		if reflect.DeepEqual(proxies, hp.cachedProxies) {
			continue
		}
		hp.cachedProxies = proxies
		hp.g.SetProxies(proxies)
	}
}

func NewHTTP2Ping(option *GroupCommonOption, providers []provider.ProxyProvider, cfg *http2ping.Config) *HTTP2Ping {
	hp := &HTTP2Ping{
		GroupBase: NewGroupBase(GroupBaseOption{
			outbound.BaseOption{
				Name:        option.Name,
				Type:        C.Fallback,
				Interface:   option.Interface,
				RoutingMark: option.RoutingMark,
			},
			option.Filter,
			option.ExcludeFilter,
			option.ExcludeType,
			providers,
		}),
		g: http2ping.NewHTTP2PingGroup(cfg),
	}
	go hp.pollForProviderProxiesUpdate(providers)
	return hp
}

func parseHTTP2PingOption(m map[string]any) *http2ping.Config {
	config := http2ping.Config{}

	interval := 1000
	if v, ok := m["interval"]; ok {
		if i, ok := v.(int); ok {
			if i <= 0 {
				panic("`interval` must be greater than zero")
			}
			interval = i
		}
	}
	config.Interval = time.Millisecond * time.Duration(interval)

	tolerance := 0
	if v, ok := m["tolerance"]; ok {
		if t, ok := v.(int); ok {
			if t < 0 {
				panic("`tolerance` can't be negative number")
			}
			tolerance = t
		}
	}
	config.Tolerance = time.Millisecond * time.Duration(tolerance)

	// For testing the usage of http2 server, using cli tool `h2i`:
	//
	// # h2i google.com
	// # ping
	server := "https://cloudflare.com"
	if v, ok := m["server"]; ok {
		if s, ok := v.(string); ok {
			server = s
		}
	}
	if u, err := url.Parse(server); err != nil {
		panic("invalid http2ping server: " + server)
	} else {
		config.HTTP2Server = u
	}
	return &config
}
