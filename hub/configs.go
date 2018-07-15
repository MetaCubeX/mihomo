package hub

import (
	"fmt"
	"net/http"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/proxy"
	T "github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs)
	r.Put("/", updateConfigs)
	return r
}

var modeMapping = map[string]T.Mode{
	"Global": T.Global,
	"Rule":   T.Rule,
	"Direct": T.Direct,
}

func getConfigs(w http.ResponseWriter, r *http.Request) {
	info := listener.Info()
	mode := tunnel.GetMode().String()
	info.Mode = &mode
	render.JSON(w, r, info)
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	general := &C.General{}
	err := render.DecodeJSON(r.Body, general)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: "Format error",
		})
		return
	}

	// update errors
	var proxyErr, modeErr error

	// update proxy
	listener := proxy.Instance()
	proxyErr = listener.Update(general.AllowLan, general.Port, general.SocksPort)

	// update mode
	if general.Mode != nil {
		mode, ok := modeMapping[*general.Mode]
		if !ok {
			modeErr = fmt.Errorf("Mode error")
		} else {
			tunnel.SetMode(mode)
		}
	}

	hasError, errors := formatErrors(map[string]error{
		"proxy": proxyErr,
		"mode":  modeErr,
	})

	if hasError {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, errors)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
