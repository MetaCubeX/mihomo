package provider

import (
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type classicalStrategy struct {
	rules           []C.Rule
	count           int
	shouldResolveIP bool
	parse           func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error)
}

func (c *classicalStrategy) Match(metadata *C.Metadata) bool {
	for _, rule := range c.rules {
		if rule.Match(metadata) {
			return true
		}
	}

	return false
}

func (c *classicalStrategy) Count() int {
	return c.count
}

func (c *classicalStrategy) ShouldResolveIP() bool {
	return c.shouldResolveIP
}

func (c *classicalStrategy) OnUpdate(rules []string) {
	var classicalRules []C.Rule
	shouldResolveIP := false
	for _, rawRule := range rules {
		ruleType, rule, params := ruleParse(rawRule)
		r, err := c.parse(ruleType, rule, "", params)
		if err != nil {
			log.Warnln("parse rule error:[%s]", err.Error())
		} else {
			if !shouldResolveIP {
				shouldResolveIP = r.ShouldResolveIP()
			}

			classicalRules = append(classicalRules, r)
		}
	}

	c.rules = classicalRules
	c.count = len(classicalRules)
}

func NewClassicalStrategy(parse func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error)) *classicalStrategy {
	return &classicalStrategy{rules: []C.Rule{}, parse: func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error) {
		switch tp {
		case "MATCH":
			return nil, fmt.Errorf("unsupported rule type on rule-set")
		default:
			return parse(tp, payload, target, params)
		}
	}}
}
