package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Dreamacro/clash/adapters/outbound"
	"github.com/Dreamacro/clash/adapters/provider"
	"github.com/Dreamacro/clash/common/singledo"
	C "github.com/Dreamacro/clash/constant"
)

type Selector struct {
	*outbound.Base
	single    *singledo.Single
	selected  C.Proxy
	providers []provider.ProxyProvider
}

func (s *Selector) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := s.selected.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(s)
	}
	return c, err
}

func (s *Selector) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := s.selected.DialUDP(metadata)
	if err == nil {
		pc.AppendToChains(s)
	}
	return pc, err
}

func (s *Selector) SupportUDP() bool {
	return s.selected.SupportUDP()
}

func (s *Selector) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range s.proxies() {
		all = append(all, proxy.Name())
	}

	return json.Marshal(map[string]interface{}{
		"type": s.Type().String(),
		"now":  s.Now(),
		"all":  all,
	})
}

func (s *Selector) Now() string {
	return s.selected.Name()
}

func (s *Selector) Set(name string) error {
	for _, proxy := range s.proxies() {
		if proxy.Name() == name {
			s.selected = proxy
			return nil
		}
	}

	return errors.New("Proxy does not exist")
}

func (s *Selector) proxies() []C.Proxy {
	elm, _, _ := s.single.Do(func() (interface{}, error) {
		return getProvidersProxies(s.providers), nil
	})

	return elm.([]C.Proxy)
}

func NewSelector(name string, providers []provider.ProxyProvider) *Selector {
	selected := providers[0].Proxies()[0]
	return &Selector{
		Base:      outbound.NewBase(name, C.Selector, false),
		single:    singledo.NewSingle(defaultGetProxiesDuration),
		providers: providers,
		selected:  selected,
	}
}
