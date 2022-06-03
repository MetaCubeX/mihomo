package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/common/convert"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"

	"gopkg.in/yaml.v3"
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// ProxySetProvider for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	*fetcher[[]C.Proxy]
	proxies        []C.Proxy
	healthCheck    *HealthCheck
	providersInUse []types.ProxyProvider
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        pp.Name(),
		"type":        pp.Type().String(),
		"vehicleType": pp.VehicleType().String(),
		"proxies":     pp.Proxies(),
		"updatedAt":   pp.updatedAt,
	})
}

func (pp *proxySetProvider) Name() string {
	return pp.name
}

func (pp *proxySetProvider) HealthCheck() {
	pp.healthCheck.check()
}

func (pp *proxySetProvider) Update() error {
	elm, same, err := pp.fetcher.Update()
	if err == nil && !same {
		pp.onUpdate(elm)
	}
	return err
}

func (pp *proxySetProvider) Initial() error {
	elm, err := pp.fetcher.Initial()
	if err != nil {
		return err
	}

	pp.onUpdate(elm)
	return nil
}

func (pp *proxySetProvider) Type() types.ProviderType {
	return types.Proxy
}

func (pp *proxySetProvider) Proxies() []C.Proxy {
	return pp.proxies
}

func (pp *proxySetProvider) ProxiesWithTouch() []C.Proxy {
	pp.healthCheck.touch()
	return pp.Proxies()
}

func (pp *proxySetProvider) setProxies(proxies []C.Proxy) {
	pp.proxies = proxies
	pp.healthCheck.setProxy(proxies)

	for _, use := range pp.providersInUse {
		_ = use.Update()
	}
}

func (pp *proxySetProvider) RegisterProvidersInUse(providers ...types.ProxyProvider) {
	pp.providersInUse = append(pp.providersInUse, providers...)
}

func stopProxyProvider(pd *ProxySetProvider) {
	pd.healthCheck.close()
	_ = pd.fetcher.Destroy()
}

func NewProxySetProvider(name string, interval time.Duration, filter string, vehicle types.Vehicle, hc *HealthCheck, forceCertVerify bool, prefixName string) (*ProxySetProvider, error) {
	filterReg, err := regexp.Compile(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter regex: %w", err)
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &proxySetProvider{
		proxies:     []C.Proxy{},
		healthCheck: hc,
	}

	fetcher := newFetcher[[]C.Proxy](name, interval, vehicle, proxiesParseAndFilter(filter, filterReg, forceCertVerify, prefixName), proxiesOnUpdate(pd))
	pd.fetcher = fetcher

	wrapper := &ProxySetProvider{pd}
	runtime.SetFinalizer(wrapper, stopProxyProvider)
	return wrapper, nil
}

// CompatibleProvider for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	name        string
	healthCheck *HealthCheck
	proxies     []C.Proxy
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        cp.Name(),
		"type":        cp.Type().String(),
		"vehicleType": cp.VehicleType().String(),
		"proxies":     cp.Proxies(),
	})
}

func (cp *compatibleProvider) Name() string {
	return cp.name
}

func (cp *compatibleProvider) HealthCheck() {
	cp.healthCheck.check()
}

func (cp *compatibleProvider) Update() error {
	return nil
}

func (cp *compatibleProvider) Initial() error {
	return nil
}

func (cp *compatibleProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func (cp *compatibleProvider) Type() types.ProviderType {
	return types.Proxy
}

func (cp *compatibleProvider) Proxies() []C.Proxy {
	return cp.proxies
}

func (cp *compatibleProvider) ProxiesWithTouch() []C.Proxy {
	cp.healthCheck.touch()
	return cp.Proxies()
}

func stopCompatibleProvider(pd *CompatibleProvider) {
	pd.healthCheck.close()
}

func NewCompatibleProvider(name string, proxies []C.Proxy, hc *HealthCheck) (*CompatibleProvider, error) {
	if len(proxies) == 0 {
		return nil, errors.New("provider need one proxy at least")
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &compatibleProvider{
		name:        name,
		proxies:     proxies,
		healthCheck: hc,
	}

	wrapper := &CompatibleProvider{pd}
	runtime.SetFinalizer(wrapper, stopCompatibleProvider)
	return wrapper, nil
}

// ProxyFilterProvider for filter provider
type ProxyFilterProvider struct {
	*proxyFilterProvider
}

type proxyFilterProvider struct {
	name        string
	psd         *ProxySetProvider
	proxies     []C.Proxy
	filter      *regexp.Regexp
	healthCheck *HealthCheck
}

func (pf *proxyFilterProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        pf.Name(),
		"type":        pf.Type().String(),
		"vehicleType": pf.VehicleType().String(),
		"proxies":     pf.Proxies(),
	})
}

func (pf *proxyFilterProvider) Name() string {
	return pf.name
}

func (pf *proxyFilterProvider) HealthCheck() {
	pf.healthCheck.check()
}

func (pf *proxyFilterProvider) Update() error {
	var proxies []C.Proxy
	if pf.filter != nil {
		for _, proxy := range pf.psd.Proxies() {
			if !pf.filter.MatchString(proxy.Name()) {
				continue
			}
			proxies = append(proxies, proxy)
		}
	} else {
		proxies = pf.psd.Proxies()
	}

	pf.proxies = proxies
	pf.healthCheck.setProxy(proxies)
	return nil
}

func (pf *proxyFilterProvider) Initial() error {
	return nil
}

func (pf *proxyFilterProvider) VehicleType() types.VehicleType {
	return pf.psd.VehicleType()
}

func (pf *proxyFilterProvider) Type() types.ProviderType {
	return types.Proxy
}

func (pf *proxyFilterProvider) Proxies() []C.Proxy {
	return pf.proxies
}

func (pf *proxyFilterProvider) ProxiesWithTouch() []C.Proxy {
	pf.healthCheck.touch()
	return pf.Proxies()
}

func stopProxyFilterProvider(pf *ProxyFilterProvider) {
	pf.healthCheck.close()
}

func NewProxyFilterProvider(name string, psd *ProxySetProvider, hc *HealthCheck, filterRegx *regexp.Regexp) *ProxyFilterProvider {
	pd := &proxyFilterProvider{
		psd:         psd,
		name:        name,
		healthCheck: hc,
		filter:      filterRegx,
	}

	_ = pd.Update()

	if hc.auto() {
		go hc.process()
	}

	wrapper := &ProxyFilterProvider{pd}
	runtime.SetFinalizer(wrapper, stopProxyFilterProvider)
	return wrapper
}

func proxiesOnUpdate(pd *proxySetProvider) func([]C.Proxy) {
	return func(elm []C.Proxy) {
		pd.setProxies(elm)
	}
}

func proxiesParseAndFilter(filter string, filterReg *regexp.Regexp, forceCertVerify bool, prefixName string) parser[[]C.Proxy] {
	return func(buf []byte) ([]C.Proxy, error) {
		schema := &ProxySchema{}

		if err := yaml.Unmarshal(buf, schema); err != nil {
			proxies, err1 := convert.ConvertsV2Ray(buf)
			if err1 != nil {
				return nil, fmt.Errorf("%s, %w", err.Error(), err1)
			}
			schema.Proxies = proxies
		}

		if schema.Proxies == nil {
			return nil, errors.New("file must have a `proxies` field")
		}

		proxies := []C.Proxy{}
		for idx, mapping := range schema.Proxies {
			if name, ok := mapping["name"]; ok && len(filter) > 0 && !filterReg.MatchString(name.(string)) {
				continue
			}

			if prefixName != "" {
				mapping["name"] = prefixName + mapping["name"].(string)
			}

			proxy, err := adapter.ParseProxy(mapping, forceCertVerify)
			if err != nil {
				return nil, fmt.Errorf("proxy %d error: %w", idx, err)
			}
			proxies = append(proxies, proxy)
		}

		if len(proxies) == 0 {
			if len(filter) > 0 {
				return nil, errors.New("doesn't match any proxy, please check your filter")
			}
			return nil, errors.New("file doesn't have any proxy")
		}

		return proxies, nil
	}
}
