package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/component/trie"
	"runtime"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"

	"gopkg.in/yaml.v2"
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]interface{} `yaml:"proxies"`
}

// for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	*fetcher
	proxies     []C.Proxy
	healthCheck *HealthCheck
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
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

func proxiesParse(buf []byte) (interface{}, error) {
	schema := &ProxySchema{}

	if err := yaml.Unmarshal(buf, schema); err != nil {
		return nil, err
	}

	if schema.Proxies == nil {
		return nil, errors.New("file must have a `proxies` field")
	}

	proxies := []C.Proxy{}
	for idx, mapping := range schema.Proxies {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d error: %w", idx, err)
		}
		proxies = append(proxies, proxy)
	}

	if len(proxies) == 0 {
		return nil, errors.New("file doesn't have any valid proxy")
	}

	return proxies, nil
}

func (pp *proxySetProvider) setProxies(proxies []C.Proxy) {
	pp.proxies = proxies
	pp.healthCheck.setProxy(proxies)
	if pp.healthCheck.auto() {
		go pp.healthCheck.check()
	}
}

func stopProxyProvider(pd *ProxySetProvider) {
	pd.healthCheck.close()
	pd.fetcher.Destroy()
}

func NewProxySetProvider(name string, interval time.Duration, vehicle types.Vehicle, hc *HealthCheck) *ProxySetProvider {
	if hc.auto() {
		go hc.process()
	}

	pd := &proxySetProvider{
		proxies:     []C.Proxy{},
		healthCheck: hc,
	}

	onUpdate := func(elm interface{}) error {
		ret := elm.([]C.Proxy)
		pd.setProxies(ret)
		return nil
	}

	fetcher := newFetcher(name, interval, vehicle, proxiesParse, onUpdate)
	pd.fetcher = fetcher

	wrapper := &ProxySetProvider{pd}
	runtime.SetFinalizer(wrapper, stopProxyProvider)
	return wrapper
}

// for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	name        string
	healthCheck *HealthCheck
	proxies     []C.Proxy
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
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

// Rule

type Behavior int

var (
	parse = func(ruleType, rule string, params []string) (C.Rule, error) {
		return nil, errors.New("unimplemented function")
	}

	ruleProviders = map[string]types.RuleProvider{}
)

func SetClassicalRuleParser(function func(ruleType, rule string, params []string) (C.Rule, error)) {
	parse = function
}

func RuleProviders() map[string]types.RuleProvider {
	return ruleProviders
}

func SetRuleProvider(ruleProvider types.RuleProvider) {
	if ruleProvider != nil {
		ruleProviders[(ruleProvider).Name()] = ruleProvider
	}
}

type ruleSetProvider struct {
	*fetcher
	behavior       Behavior
	count          int
	DomainRules    *trie.DomainTrie
	IPCIDRRules    *trie.IpCidrTrie
	ClassicalRules []C.Rule
}

type RuleSetProvider struct {
	*ruleSetProvider
}

func (r RuleSetProvider) Behavior() types.RuleType {
	//TODO implement me
	panic("implement me")
}

func (r RuleSetProvider) ShouldResolveIP() bool {
	//TODO implement me
	panic("implement me")
}

func (r RuleSetProvider) AsRule(adaptor string) C.Rule {
	//TODO implement me
	panic("implement me")
}

func NewRuleSetProvider(name string, behavior Behavior, interval time.Duration, vehicle types.Vehicle) *RuleSetProvider {
	rp := &ruleSetProvider{
		behavior: behavior,
	}

	onUpdate := func(elm interface{}) error {
		rulesRaw := elm.([]string)
		rp.count = len(rulesRaw)
		rules, err := constructRules(rp.behavior, rulesRaw)
		if err != nil {
			return err
		}
		rp.setRules(rules)
		return nil
	}

	fetcher := newFetcher(name, interval, vehicle, rulesParse, onUpdate)
	rp.fetcher = fetcher
	wrapper := &RuleSetProvider{
		rp,
	}

	runtime.SetFinalizer(wrapper, stopRuleSetProvider)
	return wrapper
}

func (rp *ruleSetProvider) Name() string {
	return rp.name
}

func (rp *ruleSetProvider) RuleCount() int {
	return rp.count
}

const (
	Domain = iota
	IPCIDR
	Classical
)

// RuleType defined

func (b Behavior) String() string {
	switch b {
	case Domain:
		return "Domain"
	case IPCIDR:
		return "IPCIDR"
	case Classical:
		return "Classical"
	default:
		return ""
	}
}

func (rp *ruleSetProvider) Match(metadata *C.Metadata) bool {
	switch rp.behavior {
	case Domain:
		return rp.DomainRules.Search(metadata.Host) != nil
	case IPCIDR:
		return rp.IPCIDRRules.IsContain(metadata.DstIP)
	case Classical:
		for _, rule := range rp.ClassicalRules {
			if rule.Match(metadata) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (rp *ruleSetProvider) Behavior() Behavior {
	return rp.behavior
}

func (rp *ruleSetProvider) VehicleType() types.VehicleType {
	return rp.vehicle.Type()
}

func (rp *ruleSetProvider) Type() types.ProviderType {
	return types.Rule
}

func (rp *ruleSetProvider) Initial() error {
	elm, err := rp.fetcher.Initial()
	if err != nil {
		return err
	}
	return rp.fetcher.onUpdate(elm)
}

func (rp *ruleSetProvider) Update() error {
	elm, same, err := rp.fetcher.Update()
	if err == nil && !same {
		return rp.fetcher.onUpdate(elm)
	}
	return err
}

func (rp *ruleSetProvider) setRules(rules interface{}) {
	switch rp.behavior {
	case Domain:
		rp.DomainRules = rules.(*trie.DomainTrie)
	case Classical:
		rp.ClassicalRules = rules.([]C.Rule)
	case IPCIDR:
		rp.IPCIDRRules = rules.(*trie.IpCidrTrie)
	default:
	}
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]interface{}{
			"behavior":    rp.behavior.String(),
			"name":        rp.Name(),
			"ruleCount":   rp.RuleCount(),
			"type":        rp.Type().String(),
			"updatedAt":   rp.updatedAt,
			"vehicleType": rp.VehicleType().String(),
		})
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Rules []string `yaml:"payload"`
}

func rulesParse(buf []byte) (interface{}, error) {
	rulePayload := RulePayload{}
	err := yaml.Unmarshal(buf, &rulePayload)
	if err != nil {
		return nil, err
	}

	return rulePayload.Rules, nil
}

func constructRules(behavior Behavior, rules []string) (interface{}, error) {
	switch behavior {
	case Domain:
		return handleDomainRules(rules)
	case IPCIDR:
		return handleIpCidrRules(rules)
	case Classical:
		return handleClassicalRules(rules)
	default:
		return nil, errors.New("unknown behavior type")
	}
}

func handleDomainRules(rules []string) (interface{}, error) {
	domainRules := trie.New()
	for _, rawRule := range rules {
		ruleType, rule, _ := ruleParse(rawRule)
		if ruleType != "" {
			return nil, errors.New("error format of domain")
		}

		if err := domainRules.Insert(rule, ""); err != nil {
			return nil, err
		}
	}
	return domainRules, nil
}

func handleIpCidrRules(rules []string) (interface{}, error) {
	ipCidrRules := trie.NewIpCidrTrie()
	for _, rawRule := range rules {
		ruleType, rule, _ := ruleParse(rawRule)
		if ruleType != "" {
			return nil, errors.New("error format of ip-cidr")
		}

		if err := ipCidrRules.AddIpCidrForString(rule); err != nil {
			return nil, err
		}
	}
	return ipCidrRules, nil
}

func handleClassicalRules(rules []string) (interface{}, error) {
	var classicalRules []C.Rule
	for _, rawRule := range rules {
		ruleType, rule, params := ruleParse(rawRule)
		if ruleType == "RULE-SET" {
			return nil, errors.New("error rule type")
		}

		r, err := parse(ruleType, rule, params)
		if err != nil {
			return nil, err
		}

		classicalRules = append(classicalRules, r)
	}
	return classicalRules, nil
}

func ruleParse(ruleRaw string) (string, string, []string) {
	item := strings.Split(ruleRaw, ",")
	if len(item) == 1 {
		return "", item[0], nil
	} else if len(item) == 2 {
		return item[0], item[1], nil
	} else if len(item) > 2 {
		return item[0], item[1], item[2:]
	}

	return "", "", nil
}

func stopRuleSetProvider(rp *RuleSetProvider) {
	rp.fetcher.Destroy()
}
