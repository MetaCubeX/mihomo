package adapters

import (
	"errors"

	C "github.com/Dreamacro/clash/constant"
)

type Selector struct {
	name     string
	selected C.Proxy
	proxys   map[string]C.Proxy
}

func (s *Selector) Name() string {
	return s.name
}

func (s *Selector) Type() C.AdapterType {
	return C.Selector
}

func (s *Selector) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	return s.selected.Generator(addr)
}

func (s *Selector) Now() string {
	return s.selected.Name()
}

func (s *Selector) All() []string {
	var all []string
	for k, _ := range s.proxys {
		all = append(all, k)
	}
	return all
}

func (s *Selector) Set(name string) error {
	proxy, exist := s.proxys[name]
	if !exist {
		return errors.New("Proxy does not exist")
	}
	s.selected = proxy
	return nil
}

func NewSelector(name string, proxys map[string]C.Proxy) (*Selector, error) {
	if len(proxys) == 0 {
		return nil, errors.New("Provide at least one proxy")
	}

	mapping := make(map[string]C.Proxy)
	var init string
	for k, v := range proxys {
		mapping[k] = v
		init = k
	}
	s := &Selector{
		name:     name,
		proxys:   mapping,
		selected: proxys[init],
	}
	return s, nil
}
