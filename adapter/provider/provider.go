package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	types "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v3"
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

type providerForApi struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	VehicleType      string            `json:"vehicleType"`
	Proxies          []C.Proxy         `json:"proxies"`
	TestUrl          string            `json:"testUrl"`
	ExpectedStatus   string            `json:"expectedStatus"`
	UpdatedAt        time.Time         `json:"updatedAt,omitempty"`
	SubscriptionInfo *SubscriptionInfo `json:"subscriptionInfo,omitempty"`
}

type baseProvider struct {
	name        string
	proxies     []C.Proxy
	healthCheck *HealthCheck
	version     uint32
}

func (bp *baseProvider) Name() string {
	return bp.name
}

func (bp *baseProvider) Version() uint32 {
	return bp.version
}

func (bp *baseProvider) HealthCheck() {
	bp.healthCheck.check()
}

func (bp *baseProvider) Type() types.ProviderType {
	return types.Proxy
}

func (bp *baseProvider) Proxies() []C.Proxy {
	return bp.proxies
}

func (bp *baseProvider) Count() int {
	return len(bp.proxies)
}

func (bp *baseProvider) Touch() {
	bp.healthCheck.touch()
}

func (bp *baseProvider) HealthCheckURL() string {
	return bp.healthCheck.url
}

func (bp *baseProvider) RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	bp.healthCheck.registerHealthCheckTask(url, expectedStatus, filter, interval)
}

func (bp *baseProvider) setProxies(proxies []C.Proxy) {
	bp.proxies = proxies
	bp.healthCheck.setProxy(proxies)
	if bp.healthCheck.auto() {
		go bp.healthCheck.check()
	}
}

func (bp *baseProvider) Close() error {
	bp.healthCheck.close()
	return nil
}

// ProxySetProvider for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	baseProvider
	*resource.Fetcher[[]C.Proxy]
	subscriptionInfo *SubscriptionInfo
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(providerForApi{
		Name:             pp.Name(),
		Type:             pp.Type().String(),
		VehicleType:      pp.VehicleType().String(),
		Proxies:          pp.Proxies(),
		TestUrl:          pp.healthCheck.url,
		ExpectedStatus:   pp.healthCheck.expectedStatus.String(),
		UpdatedAt:        pp.UpdatedAt(),
		SubscriptionInfo: pp.subscriptionInfo,
	})
}

func (pp *proxySetProvider) Name() string {
	return pp.Fetcher.Name()
}

func (pp *proxySetProvider) Update() error {
	_, _, err := pp.Fetcher.Update()
	return err
}

func (pp *proxySetProvider) Initial() error {
	_, err := pp.Fetcher.Initial()
	if err != nil {
		return err
	}
	if subscriptionInfo := cachefile.Cache().GetSubscriptionInfo(pp.Name()); subscriptionInfo != "" {
		pp.subscriptionInfo.Update(subscriptionInfo)
	}
	pp.closeAllConnections()
	return nil
}

func (pp *proxySetProvider) closeAllConnections() {
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		for _, chain := range c.Chains() {
			if chain == pp.Name() {
				_ = c.Close()
				break
			}
		}
		return true
	})
}

func (pp *proxySetProvider) Close() error {
	_ = pp.baseProvider.Close()
	return pp.Fetcher.Close()
}

func NewProxySetProvider(name string, interval time.Duration, parser resource.Parser[[]C.Proxy], vehicle types.Vehicle, hc *HealthCheck) (*ProxySetProvider, error) {
	if hc.auto() {
		go hc.process()
	}

	si := new(SubscriptionInfo)
	pd := &proxySetProvider{
		baseProvider: baseProvider{
			name:        name,
			proxies:     []C.Proxy{},
			healthCheck: hc,
		},
		subscriptionInfo: si,
	}

	fetcher := resource.NewFetcher[[]C.Proxy](name, interval, vehicle, parser, proxiesOnUpdate(pd))
	pd.Fetcher = fetcher
	if httpVehicle, ok := vehicle.(*resource.HTTPVehicle); ok {
		httpVehicle.SetInRead(func(resp *http.Response) {
			if subscriptionInfo := resp.Header.Get("subscription-userinfo"); subscriptionInfo != "" {
				cachefile.Cache().SetSubscriptionInfo(name, subscriptionInfo)
				si.Update(subscriptionInfo)
			}
		})
	}

	wrapper := &ProxySetProvider{pd}
	runtime.SetFinalizer(wrapper, (*ProxySetProvider).Close)
	return wrapper, nil
}

func (pp *ProxySetProvider) Close() error {
	runtime.SetFinalizer(pp, nil)
	return pp.proxySetProvider.Close()
}

// InlineProvider for auto gc
type InlineProvider struct {
	*inlineProvider
}

type inlineProvider struct {
	baseProvider
	updateAt time.Time
}

func (ip *inlineProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(providerForApi{
		Name:           ip.Name(),
		Type:           ip.Type().String(),
		VehicleType:    ip.VehicleType().String(),
		Proxies:        ip.Proxies(),
		TestUrl:        ip.healthCheck.url,
		ExpectedStatus: ip.healthCheck.expectedStatus.String(),
		UpdatedAt:      ip.updateAt,
	})
}

func (ip *inlineProvider) VehicleType() types.VehicleType {
	return types.Inline
}

func (ip *inlineProvider) Initial() error {
	return nil
}

func (ip *inlineProvider) Update() error {
	// make api update happy
	ip.updateAt = time.Now()
	return nil
}

func NewInlineProvider(name string, payload []map[string]any, parser resource.Parser[[]C.Proxy], hc *HealthCheck) (*InlineProvider, error) {
	if hc.auto() {
		go hc.process()
	}

	ps := ProxySchema{Proxies: payload}
	buf, err := yaml.Marshal(ps)
	if err != nil {
		return nil, err
	}
	proxies, err := parser(buf)
	if err != nil {
		return nil, err
	}

	ip := &inlineProvider{
		baseProvider: baseProvider{
			name:        name,
			proxies:     proxies,
			healthCheck: hc,
		},
		updateAt: time.Now(),
	}
	wrapper := &InlineProvider{ip}
	runtime.SetFinalizer(wrapper, (*InlineProvider).Close)
	return wrapper, nil
}

func (ip *InlineProvider) Close() error {
	runtime.SetFinalizer(ip, nil)
	return ip.baseProvider.Close()
}

// CompatibleProvider for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	baseProvider
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(providerForApi{
		Name:           cp.Name(),
		Type:           cp.Type().String(),
		VehicleType:    cp.VehicleType().String(),
		Proxies:        cp.Proxies(),
		TestUrl:        cp.healthCheck.url,
		ExpectedStatus: cp.healthCheck.expectedStatus.String(),
	})
}

func (cp *compatibleProvider) Update() error {
	return nil
}

func (cp *compatibleProvider) Initial() error {
	if cp.healthCheck.interval != 0 && cp.healthCheck.url != "" {
		cp.HealthCheck()
	}
	return nil
}

func (cp *compatibleProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func NewCompatibleProvider(name string, proxies []C.Proxy, hc *HealthCheck) (*CompatibleProvider, error) {
	if len(proxies) == 0 {
		return nil, errors.New("provider need one proxy at least")
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &compatibleProvider{
		baseProvider: baseProvider{
			name:        name,
			proxies:     proxies,
			healthCheck: hc,
		},
	}

	wrapper := &CompatibleProvider{pd}
	runtime.SetFinalizer(wrapper, (*CompatibleProvider).Close)
	return wrapper, nil
}

func (cp *CompatibleProvider) Close() error {
	runtime.SetFinalizer(cp, nil)
	return cp.compatibleProvider.Close()
}

func proxiesOnUpdate(pd *proxySetProvider) func([]C.Proxy) {
	return func(elm []C.Proxy) {
		pd.setProxies(elm)
		pd.version += 1
	}
}

func NewProxiesParser(filter string, excludeFilter string, excludeType string, dialerProxy string, override OverrideSchema) (resource.Parser[[]C.Proxy], error) {
	excludeFilterReg, err := regexp2.Compile(excludeFilter, regexp2.None)
	if err != nil {
		return nil, fmt.Errorf("invalid excludeFilter regex: %w", err)
	}
	var excludeTypeArray []string
	if excludeType != "" {
		excludeTypeArray = strings.Split(excludeType, "|")
	}

	var filterRegs []*regexp2.Regexp
	for _, filter := range strings.Split(filter, "`") {
		filterReg, err := regexp2.Compile(filter, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
		filterRegs = append(filterRegs, filterReg)
	}

	return func(buf []byte) ([]C.Proxy, error) {
		schema := &ProxySchema{}

		if err := yaml.Unmarshal(buf, schema); err != nil {
			proxies, err1 := convert.ConvertsV2Ray(buf)
			if err1 != nil {
				return nil, fmt.Errorf("%w, %w", err, err1)
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
					if mat, _ := excludeFilterReg.MatchString(name); mat {
						continue
					}
				}
				if len(filter) > 0 {
					if mat, _ := filterReg.MatchString(name); !mat {
						continue
					}
				}
				if _, ok := proxiesSet[name]; ok {
					continue
				}

				if len(dialerProxy) > 0 {
					mapping["dialer-proxy"] = dialerProxy
				}

				val := reflect.ValueOf(override)
				for i := 0; i < val.NumField(); i++ {
					field := val.Field(i)
					if field.IsNil() {
						continue
					}
					fieldName := strings.Split(val.Type().Field(i).Tag.Get("provider"), ",")[0]
					switch fieldName {
					case "additional-prefix":
						name := mapping["name"].(string)
						mapping["name"] = *field.Interface().(*string) + name
					case "additional-suffix":
						name := mapping["name"].(string)
						mapping["name"] = name + *field.Interface().(*string)
					case "proxy-name":
						// Iterate through all naming replacement rules and perform the replacements.
						for _, expr := range override.ProxyName {
							name := mapping["name"].(string)
							newName, err := expr.Pattern.Replace(name, expr.Target, 0, -1)
							if err != nil {
								return nil, fmt.Errorf("proxy name replace error: %w", err)
							}
							mapping["name"] = newName
						}
					default:
						mapping[fieldName] = field.Elem().Interface()
					}
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
	}, nil
}
