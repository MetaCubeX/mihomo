package provider

import (
	"encoding/json"
	"github.com/Dreamacro/clash/component/resource"
	C "github.com/Dreamacro/clash/constant"
	P "github.com/Dreamacro/clash/constant/provider"
	"gopkg.in/yaml.v3"
	"runtime"
	"time"
)

var (
	ruleProviders = map[string]P.RuleProvider{}
)

type ruleSetProvider struct {
	*resource.Fetcher[any]
	behavior P.RuleType
	strategy ruleStrategy
}

type RuleSetProvider struct {
	*ruleSetProvider
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Rules  []string `yaml:"payload"`
	Rules2 []string `yaml:"rules"`
}

type ruleStrategy interface {
	Match(metadata *C.Metadata) bool
	Count() int
	ShouldResolveIP() bool
	ShouldFindProcess() bool
	OnUpdate(rules []string)
}

func RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

func SetRuleProvider(ruleProvider P.RuleProvider) {
	if ruleProvider != nil {
		ruleProviders[(ruleProvider).Name()] = ruleProvider
	}
}

func (rp *ruleSetProvider) Type() P.ProviderType {
	return P.Rule
}

func (rp *ruleSetProvider) Initial() error {
	elm, err := rp.Fetcher.Initial()
	if err != nil {
		return err
	}

	rp.OnUpdate(elm)
	return nil
}

func (rp *ruleSetProvider) Update() error {
	elm, same, err := rp.Fetcher.Update()
	if err == nil && !same {
		rp.OnUpdate(elm)
		return nil
	}

	return err
}

func (rp *ruleSetProvider) Behavior() P.RuleType {
	return rp.behavior
}

func (rp *ruleSetProvider) Match(metadata *C.Metadata) bool {
	return rp.strategy != nil && rp.strategy.Match(metadata)
}

func (rp *ruleSetProvider) ShouldResolveIP() bool {
	return rp.strategy.ShouldResolveIP()
}

func (rp *ruleSetProvider) ShouldFindProcess() bool {
	return rp.strategy.ShouldFindProcess()
}

func (rp *ruleSetProvider) AsRule(adaptor string) C.Rule {
	panic("implement me")
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]interface{}{
			"behavior":    rp.behavior.String(),
			"name":        rp.Name(),
			"ruleCount":   rp.strategy.Count(),
			"type":        rp.Type().String(),
			"updatedAt":   rp.UpdatedAt,
			"vehicleType": rp.VehicleType().String(),
		})
}

func NewRuleSetProvider(name string, behavior P.RuleType, interval time.Duration, vehicle P.Vehicle,
	parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) P.RuleProvider {
	rp := &ruleSetProvider{
		behavior: behavior,
	}

	onUpdate := func(elm interface{}) {
		rulesRaw := elm.([]string)
		rp.strategy.OnUpdate(rulesRaw)
	}

	fetcher := resource.NewFetcher(name, interval, vehicle, rulesParse, onUpdate)
	rp.Fetcher = fetcher
	rp.strategy = newStrategy(behavior, parse)

	wrapper := &RuleSetProvider{
		rp,
	}

	final := func(provider *RuleSetProvider) { _ = rp.Fetcher.Destroy() }
	runtime.SetFinalizer(wrapper, final)
	return wrapper
}

func newStrategy(behavior P.RuleType, parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) ruleStrategy {
	switch behavior {
	case P.Domain:
		strategy := NewDomainStrategy()
		return strategy
	case P.IPCIDR:
		strategy := NewIPCidrStrategy()
		return strategy
	case P.Classical:
		strategy := NewClassicalStrategy(parse)
		return strategy
	default:
		return nil
	}
}

func rulesParse(buf []byte) (any, error) {
	rulePayload := RulePayload{}
	err := yaml.Unmarshal(buf, &rulePayload)
	if err != nil {
		return nil, err
	}

	return append(rulePayload.Rules, rulePayload.Rules2...), nil
}
