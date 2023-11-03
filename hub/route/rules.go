package route

import (
	"github.com/metacubex/mihomo/constant"
	"net/http"

	"github.com/metacubex/mihomo/tunnel"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)
	return r
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size"`
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rawRules := tunnel.Rules()
	rules := []Rule{}
	for _, rule := range rawRules {
		r := Rule{
			Type:    rule.RuleType().String(),
			Payload: rule.Payload(),
			Proxy:   rule.Adapter(),
			Size:    -1,
		}
		if rule.RuleType() == constant.GEOIP || rule.RuleType() == constant.GEOSITE {
			r.Size = rule.(constant.RuleGroup).GetRecodeSize()
		}
		rules = append(rules, r)

	}

	render.JSON(w, r, render.M{
		"rules": rules,
	})
}
