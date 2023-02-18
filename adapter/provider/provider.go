package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/common/convert"
	clashHttp "github.com/Dreamacro/clash/component/http"
	"github.com/Dreamacro/clash/component/resource"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/log"

	"github.com/dlclark/regexp2"
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
	*resource.Fetcher[[]C.Proxy]
	proxies          []C.Proxy
	healthCheck      *HealthCheck
	version          uint32
	subscriptionInfo *SubscriptionInfo
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":             pp.Name(),
		"type":             pp.Type().String(),
		"vehicleType":      pp.VehicleType().String(),
		"proxies":          pp.Proxies(),
		"updatedAt":        pp.UpdatedAt,
		"subscriptionInfo": pp.subscriptionInfo,
	})
}

func (pp *proxySetProvider) Version() uint32 {
	return pp.version
}

func (pp *proxySetProvider) Name() string {
	return pp.Fetcher.Name()
}

func (pp *proxySetProvider) HealthCheck() {
	pp.healthCheck.check()
}

func (pp *proxySetProvider) Update() error {
	elm, same, err := pp.Fetcher.Update()
	if err == nil && !same {
		pp.OnUpdate(elm)
	}
	return err
}

func (pp *proxySetProvider) Initial() error {
	elm, err := pp.Fetcher.Initial()
	if err != nil {
		return err
	}
	pp.OnUpdate(elm)
	return nil
}

func (pp *proxySetProvider) Type() types.ProviderType {
	return types.Proxy
}

func (pp *proxySetProvider) Proxies() []C.Proxy {
	return pp.proxies
}

func (pp *proxySetProvider) Touch() {
	pp.healthCheck.touch()
}

func (pp *proxySetProvider) setProxies(proxies []C.Proxy) {
	pp.proxies = proxies
	pp.healthCheck.setProxy(proxies)
	if pp.healthCheck.auto() {
		defer func() { go pp.healthCheck.lazyCheck() }()
	}
}

func (pp *proxySetProvider) getSubscriptionInfo() {
	if pp.VehicleType() != types.HTTP {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
		defer cancel()
		resp, err := clashHttp.HttpRequest(ctx, pp.Vehicle().(*resource.HTTPVehicle).Url(),
			http.MethodGet, http.Header{"User-Agent": {"clash"}}, nil)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		userInfoStr := strings.TrimSpace(resp.Header.Get("subscription-userinfo"))
		if userInfoStr == "" {
			resp2, err := clashHttp.HttpRequest(ctx, pp.Vehicle().(*resource.HTTPVehicle).Url(),
				http.MethodGet, http.Header{"User-Agent": {"Quantumultx"}}, nil)
			if err != nil {
				return
			}
			defer resp2.Body.Close()
			userInfoStr = strings.TrimSpace(resp2.Header.Get("subscription-userinfo"))
			if userInfoStr == "" {
				return
			}
		}
		pp.subscriptionInfo, err = NewSubscriptionInfo(userInfoStr)
		if err != nil {
			log.Warnln("[Provider] get subscription-userinfo: %e", err)
		}
	}()
}

func stopProxyProvider(pd *ProxySetProvider) {
	pd.healthCheck.close()
	_ = pd.Fetcher.Destroy()
}

func NewProxySetProvider(name string, interval time.Duration, filter string, excludeFilter string, excludeType string, vehicle types.Vehicle, hc *HealthCheck) (*ProxySetProvider, error) {
	excludeFilterReg, err := regexp2.Compile(excludeFilter, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid excludeFilter regex: %w", err)
	}
	var excludeTypeArray []string
	if excludeType != "" {
		excludeTypeArray = strings.Split(excludeType, "|")
	}

	var filterRegs []*regexp2.Regexp
	for _, filter := range strings.Split(filter, "`") {
		filterReg, err := regexp2.Compile(filter, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
		filterRegs = append(filterRegs, filterReg)
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &proxySetProvider{
		proxies:     []C.Proxy{},
		healthCheck: hc,
	}

	fetcher := resource.NewFetcher[[]C.Proxy](name, interval, vehicle, proxiesParseAndFilter(filter, excludeFilter, excludeTypeArray, filterRegs, excludeFilterReg), proxiesOnUpdate(pd))
	pd.Fetcher = fetcher

	pd.getSubscriptionInfo()
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
	version     uint32
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        cp.Name(),
		"type":        cp.Type().String(),
		"vehicleType": cp.VehicleType().String(),
		"proxies":     cp.Proxies(),
	})
}

func (cp *compatibleProvider) Version() uint32 {
	return cp.version
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

func (cp *compatibleProvider) Touch() {
	cp.healthCheck.touch()
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

func proxiesOnUpdate(pd *proxySetProvider) func([]C.Proxy) {
	return func(elm []C.Proxy) {
		pd.setProxies(elm)
		pd.version += 1
		pd.getSubscriptionInfo()
	}
}

func proxiesParseAndFilter(filter string, excludeFilter string, excludeTypeArray []string, filterRegs []*regexp2.Regexp, excludeFilterReg *regexp2.Regexp) resource.Parser[[]C.Proxy] {
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
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range filterRegs {
			for idx, mapping := range schema.Proxies {
				if nil != excludeTypeArray && len(excludeTypeArray) > 0 {
					mType, ok := mapping["type"]
					if !ok {
						continue
					}
					pType, ok := mType.(string)
					if !ok {
						continue
					}
					flag := false
					for i := range excludeTypeArray {
						if strings.EqualFold(pType, excludeTypeArray[i]) {
							flag = true
							break
						}

					}
					if flag {
						continue
					}

				}
				mName, ok := mapping["name"]
				if !ok {
					continue
				}
				name, ok := mName.(string)
				if !ok {
					continue
				}
				if len(excludeFilter) > 0 {
					if mat, _ := excludeFilterReg.FindStringMatch(name); mat != nil {
						continue
					}
				}
				if len(filter) > 0 {
					if mat, _ := filterReg.FindStringMatch(name); mat == nil {
						continue
					}
				}
				if _, ok := proxiesSet[name]; ok {
					continue
				}
				proxy, err := adapter.ParseProxy(mapping)
				if err != nil {
					return nil, fmt.Errorf("proxy %d error: %w", idx, err)
				}
				proxiesSet[name] = struct{}{}
				proxies = append(proxies, proxy)
			}
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
