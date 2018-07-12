package hub

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)
	r.Put("/", updateRules)
	return r
}

type Rule struct {
	Name    string `json:"name"`
	Payload string `json:"type"`
}

type GetRulesResponse struct {
	Rules []Rule `json:"rules"`
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rulesCfg, _ := tun.Config()

	var rules []Rule
	for _, rule := range rulesCfg {
		rules = append(rules, Rule{
			Name:    rule.RuleType().String(),
			Payload: rule.Payload(),
		})
	}

	w.WriteHeader(http.StatusOK)
	render.JSON(w, r, GetRulesResponse{
		Rules: rules,
	})
}

func updateRules(w http.ResponseWriter, r *http.Request) {
	err := tun.UpdateConfig()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, Error{
			Error: err.Error(),
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
