package provider

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

type classicalStrategy struct {
	rules             []C.Rule
	count             int
	shouldResolveIP   bool
	shouldFindProcess bool
	parse             func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error)
}

func (c *classicalStrategy) Behavior() P.RuleBehavior {
	return P.Classical
}

func (c *classicalStrategy) Match(metadata *C.Metadata) bool {
	for _, rule := range c.rules {
		if m, _ := rule.Match(metadata); m {
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

func (c *classicalStrategy) ShouldFindProcess() bool {
	return c.shouldFindProcess
}

func (c *classicalStrategy) Reset() {
	c.rules = nil
	c.count = 0
	c.shouldFindProcess = false
	c.shouldResolveIP = false
}

func (c *classicalStrategy) Insert(rule string) {
	ruleType, rule, params := ruleParse(rule)

	if ruleType == "PROCESS-NAME" {
		c.shouldFindProcess = true
	}

	r, err := c.parse(ruleType, rule, "", params)
	if err != nil {
		log.Warnln("parse rule error:[%s]", err.Error())
	} else {
		if r.ShouldResolveIP() {
			c.shouldResolveIP = true
		}
		if r.ShouldFindProcess() {
			c.shouldFindProcess = true
		}

		c.rules = append(c.rules, r)
		c.count++
	}
}

func (c *classicalStrategy) FinishInsert() {}

func ruleParse(ruleRaw string) (string, string, []string) {
	item := strings.Split(ruleRaw, ",")
	if len(item) == 1 {
		return "", item[0], nil
	} else if len(item) == 2 {
		return item[0], item[1], nil
	} else if len(item) > 2 {
		if item[0] == "NOT" || item[0] == "OR" || item[0] == "AND" || item[0] == "SUB-RULE" || item[0] == "DOMAIN-REGEX" || item[0] == "PROCESS-NAME-REGEX" || item[0] == "PROCESS-PATH-REGEX" {
			return item[0], strings.Join(item[1:len(item)], ","), nil
		} else {
			return item[0], item[1], item[2:]
		}
	}

	return "", "", nil
}

func NewClassicalStrategy(parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) *classicalStrategy {
	return &classicalStrategy{rules: []C.Rule{}, parse: func(tp, payload, target string, params []string) (parsed C.Rule, parseErr error) {
		switch tp {
		case "MATCH":
			return nil, fmt.Errorf("unsupported rule type on rule-set")
		default:
			return parse(tp, payload, target, params, nil)
		}
	}}
}
