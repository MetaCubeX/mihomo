package rules

import (
	"fmt"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	P "github.com/Dreamacro/clash/constant/provider"
	"time"
)

func ParseRule(tp, payload, target string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
	)

	ruleExtra := &C.RuleExtra{
		Network:   findNetwork(params),
		SourceIPs: findSourceIPs(params),
	}

	switch tp {
	case "DOMAIN":
		parsed = NewDomain(payload, target, ruleExtra)
	case "DOMAIN-SUFFIX":
		parsed = NewDomainSuffix(payload, target, ruleExtra)
	case "DOMAIN-KEYWORD":
		parsed = NewDomainKeyword(payload, target, ruleExtra)
	case "GEOSITE":
		parsed, parseErr = NewGEOSITE(payload, target, ruleExtra)
	case "GEOIP":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewGEOIP(payload, target, noResolve, ruleExtra)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPCIDR(payload, target, ruleExtra, WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = NewIPCIDR(payload, target, ruleExtra, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = NewPort(payload, target, true, ruleExtra)
	case "DST-PORT":
		parsed, parseErr = NewPort(payload, target, false, ruleExtra)
	case "PROCESS-NAME":
		parsed, parseErr = NewProcess(payload, target, ruleExtra)
	case "MATCH":
		parsed = NewMatch(target, ruleExtra)
	case "RULE-SET":
		parsed, parseErr = NewRuleSet(payload, target, ruleExtra)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}

type ruleProviderSchema struct {
	Type     string `provider:"type"`
	Behavior string `provider:"behavior"`
	Path     string `provider:"path"`
	URL      string `provider:"url,omitempty"`
	Interval int    `provider:"interval,omitempty"`
}

func ParseRuleProvider(name string, mapping map[string]interface{}) (P.RuleProvider, error) {
	schema := &ruleProviderSchema{}
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}
	var behavior P.RuleType

	switch schema.Behavior {
	case "domain":
		behavior = P.Domain
	case "ipcidr":
		behavior = P.IPCIDR
	case "classical":
		behavior = P.Classical
	default:
		return nil, fmt.Errorf("unsupported behavior type: %s", schema.Behavior)
	}

	path := C.Path.Resolve(schema.Path)
	var vehicle P.Vehicle
	switch schema.Type {
	case "file":
		vehicle = provider.NewFileVehicle(path)
	case "http":
		vehicle = provider.NewHTTPVehicle(schema.URL, path)
	default:
		return nil, fmt.Errorf("unsupported vehicle type: %s", schema.Type)
	}

	return NewRuleSetProvider(name, behavior, time.Duration(uint(schema.Interval))*time.Second, vehicle), nil
}
