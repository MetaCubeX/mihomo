package hub

import (
	"net/http"

	"github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Put("/", updateConfig)
	return r
}

type General struct {
	Mode string `json:mode`
}

var modeMapping = map[string]tunnel.Mode{
	"global": tunnel.Global,
	"rule":   tunnel.Rule,
	"direct": tunnel.Direct,
}

func updateConfig(w http.ResponseWriter, r *http.Request) {
	general := &General{}
	err := render.DecodeJSON(r.Body, general)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: "Format error",
		})
		return
	}

	mode, ok := modeMapping[general.Mode]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: "Mode error",
		})
		return
	}
	tun.SetMode(mode)
	w.WriteHeader(http.StatusNoContent)
}
