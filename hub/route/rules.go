package route

import (
	"time"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)
	if !embedMode { // disallow update/patch rules in embed mode
		r.Patch("/disable", disableRules)
	}
	return r
}

type Rule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size"`

	// Extra contains information from RuleWrapper
	Extra *RuleExtra `json:"extra,omitempty"`
}

type RuleExtra struct {
	Disabled  bool      `json:"disabled"`
	HitCount  uint64    `json:"hitCount"`
	HitAt     time.Time `json:"hitAt"`
	MissCount uint64    `json:"missCount"`
	MissAt    time.Time `json:"missAt"`
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rawRules := tunnel.Rules()
	rules := make([]Rule, 0, len(rawRules))
	for index, rule := range rawRules {
		r := Rule{
			Index:   index,
			Type:    rule.RuleType().String(),
			Payload: rule.Payload(),
			Proxy:   rule.Adapter(),
			Size:    -1,
		}
		if ruleWrapper, ok := rule.(constant.RuleWrapper); ok {
			r.Extra = &RuleExtra{
				Disabled:  ruleWrapper.IsDisabled(),
				HitCount:  ruleWrapper.HitCount(),
				HitAt:     ruleWrapper.HitAt(),
				MissCount: ruleWrapper.MissCount(),
				MissAt:    ruleWrapper.MissAt(),
			}
			rule = ruleWrapper.Unwrap() // unwrap RuleWrapper
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

// disableRules disable or enable rules by their indexes.
func disableRules(w http.ResponseWriter, r *http.Request) {
	// key: rule index, value: disabled
	var payload map[int]bool
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if len(payload) != 0 {
		rules := tunnel.Rules()
		for index, disabled := range payload {
			if index < 0 || index >= len(rules) {
				continue
			}
			rule := rules[index]
			if ruleWrapper, ok := rule.(constant.RuleWrapper); ok {
				ruleWrapper.SetDisabled(disabled)
			}
		}
	}

	render.NoContent(w, r)
}
