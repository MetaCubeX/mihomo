package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type Selector struct {
	*GroupBase
	disableUDP bool
	selected   string
	testUrl    string
	Hidden     bool
	Icon       string
}

// DialContext implements C.ProxyAdapter
func (s *Selector) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := s.selectedProxy(true).DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(s)
	}
	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Selector) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := s.selectedProxy(true).ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(s)
	}
	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (s *Selector) SupportUDP() bool {
	if s.disableUDP {
		return false
	}

	return s.selectedProxy(false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (s *Selector) IsL3Protocol(metadata *C.Metadata) bool {
	return s.selectedProxy(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (s *Selector) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range s.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	// When testurl is the default value
	// do not append a value to ensure that the web dashboard follows the settings of the dashboard
	var url string
	if s.testUrl != C.DefaultTestURL {
		url = s.testUrl
	}

	return json.Marshal(map[string]any{
		"type":    s.Type().String(),
		"now":     s.Now(),
		"all":     all,
		"testUrl": url,
		"hidden":  s.Hidden,
		"icon":    s.Icon,
	})
}

func (s *Selector) Now() string {
	return s.selectedProxy(false).Name()
}

func (s *Selector) Set(name string) error {
	for _, proxy := range s.GetProxies(false) {
		if proxy.Name() == name {
			s.selected = name
			return nil
		}
	}

	return errors.New("proxy not exist")
}

func (s *Selector) ForceSet(name string) {
	s.selected = name
}

// Unwrap implements C.ProxyAdapter
func (s *Selector) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return s.selectedProxy(touch)
}

func (s *Selector) selectedProxy(touch bool) C.Proxy {
	proxies := s.GetProxies(touch)
	for _, proxy := range proxies {
		if proxy.Name() == s.selected {
			return proxy
		}
	}

	return proxies[0]
}

func (s *Selector) Providers() []P.ProxyProvider {
	return s.providers
}

func (s *Selector) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

func NewSelector(option *GroupCommonOption, providers []P.ProxyProvider) *Selector {
	return &Selector{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Selector,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			Providers:      providers,
		}),
		selected:   "COMPATIBLE",
		disableUDP: option.DisableUDP,
		testUrl:    option.URL,
		Hidden:     option.Hidden,
		Icon:       option.Icon,
	}
}
