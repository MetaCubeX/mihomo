package rules

import (
	"encoding/json"
	"errors"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	P "github.com/Dreamacro/clash/constant/provider"
	"gopkg.in/yaml.v2"
	"runtime"
	"strings"
	"time"
)

var (
	ruleProviders = map[string]P.RuleProvider{}
)

type ruleSetProvider struct {
	*fetcher
	behavior        P.RuleType
	shouldResolveIP bool
	count           int
	DomainRules     *trie.DomainTrie
	IPCIDRRules     *trie.IpCidrTrie
	ClassicalRules  []C.Rule
}

type RuleSetProvider struct {
	*ruleSetProvider
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Rules []string `yaml:"payload"`
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

func (rp *ruleSetProvider) Behavior() P.RuleType {
	return rp.behavior
}

func (rp *ruleSetProvider) Match(metadata *C.Metadata) bool {
	switch rp.behavior {
	case P.Domain:
		return rp.DomainRules.Search(metadata.Host) != nil
	case P.IPCIDR:
		return rp.IPCIDRRules.IsContain(metadata.DstIP)
	case P.Classical:
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

func (rp *ruleSetProvider) ShouldResolveIP() bool {
	return rp.shouldResolveIP
}

func (rp *ruleSetProvider) AsRule(adaptor string) C.Rule {
	panic("implement me")
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]interface{}{
			"behavior":    rp.behavior.String(),
			"name":        rp.Name(),
			"ruleCount":   rp.count,
			"type":        rp.Type().String(),
			"updatedAt":   rp.updatedAt,
			"vehicleType": rp.VehicleType().String(),
		})
}

func NewRuleSetProvider(name string, behavior P.RuleType, interval time.Duration, vehicle P.Vehicle) P.RuleProvider {
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

	runtime.SetFinalizer(wrapper, rp.fetcher.Destroy())
	return wrapper
}

func rulesParse(buf []byte) (interface{}, error) {
	rulePayload := RulePayload{}
	err := yaml.Unmarshal(buf, &rulePayload)
	if err != nil {
		return nil, err
	}

	return rulePayload.Rules, nil
}

func constructRules(behavior P.RuleType, rules []string) (interface{}, error) {
	switch behavior {
	case P.Domain:
		return handleDomainRules(rules)
	case P.IPCIDR:
		return handleIpCidrRules(rules)
	case P.Classical:
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

		r, err := ParseRule(ruleType, rule, "", params)
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

func (rp *ruleSetProvider) setRules(rules interface{}) {
	switch rp.behavior {
	case P.Domain:
		rp.DomainRules = rules.(*trie.DomainTrie)
		rp.shouldResolveIP = false
	case P.Classical:
		rp.ClassicalRules = rules.([]C.Rule)
		for i := range rp.ClassicalRules {
			if rp.ClassicalRules[i].ShouldResolveIP() {
				rp.shouldResolveIP = true
				break
			}
		}
	case P.IPCIDR:
		rp.IPCIDRRules = rules.(*trie.IpCidrTrie)
		rp.shouldResolveIP = true
	default:
		rp.shouldResolveIP = false
	}
}
