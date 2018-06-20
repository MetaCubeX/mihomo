package hub

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

type Configs struct {
	Proxys []Proxy `json:"proxys"`
	Rules  []Rule  `json:"rules"`
}

type Proxy struct {
	Name string `json:"name"`
}

type Rule struct {
	Name    string `json:"name"`
	Payload string `json:"type"`
}

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfig)
	r.Put("/", updateConfig)
	return r
}

func getConfig(w http.ResponseWriter, r *http.Request) {
	rulesCfg, proxysCfg := tun.Config()

	var (
		rules  []Rule
		proxys []Proxy
	)

	for _, rule := range rulesCfg {
		rules = append(rules, Rule{
			Name:    rule.RuleType().String(),
			Payload: rule.Payload(),
		})
	}

	for _, proxy := range proxysCfg {
		proxys = append(proxys, Proxy{Name: proxy.Name()})
	}

	w.WriteHeader(http.StatusOK)
	render.JSON(w, r, Configs{
		Rules:  rules,
		Proxys: proxys,
	})
}

func updateConfig(w http.ResponseWriter, r *http.Request) {
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
