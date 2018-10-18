package adapters

import (
	"errors"
	"sort"

	C "github.com/Dreamacro/clash/constant"
)

type Selector struct {
	name     string
	selected C.Proxy
	proxies  map[string]C.Proxy
}

type SelectorOption struct {
	Name    string   `proxy:"name"`
	Proxies []string `proxy:"proxies"`
}

func (s *Selector) Name() string {
	return s.name
}

func (s *Selector) Type() C.AdapterType {
	return C.Selector
}

func (s *Selector) Generator(metadata *C.Metadata) (adapter C.ProxyAdapter, err error) {
	return s.selected.Generator(metadata)
}

func (s *Selector) Now() string {
	return s.selected.Name()
}

func (s *Selector) All() []string {
	var all []string
	for k := range s.proxies {
		all = append(all, k)
	}
	sort.Strings(all)
	return all
}

func (s *Selector) Set(name string) error {
	proxy, exist := s.proxies[name]
	if !exist {
		return errors.New("Proxy does not exist")
	}
	s.selected = proxy
	return nil
}

func NewSelector(name string, proxies []C.Proxy) (*Selector, error) {
	if len(proxies) == 0 {
		return nil, errors.New("Provide at least one proxy")
	}

	mapping := make(map[string]C.Proxy)
	for _, proxy := range proxies {
		mapping[proxy.Name()] = proxy
	}

	s := &Selector{
		name:     name,
		proxies:  mapping,
		selected: proxies[0],
	}
	return s, nil
}
