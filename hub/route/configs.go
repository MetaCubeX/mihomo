package route

import (
	"net/http"
	"path/filepath"

	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/log"
	P "github.com/Dreamacro/clash/proxy"
	T "github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs)
	r.Put("/", updateConfigs)
	r.Patch("/", patchConfigs)
	return r
}

type configSchema struct {
	Port      *int          `json:"port"`
	SocksPort *int          `json:"socket-port"`
	RedirPort *int          `json:"redir-port"`
	AllowLan  *bool         `json:"allow-lan"`
	Mode      *T.Mode       `json:"mode"`
	LogLevel  *log.LogLevel `json:"log-level"`
}

func getConfigs(w http.ResponseWriter, r *http.Request) {
	general := executor.GetGeneral()
	render.Respond(w, r, general)
}

func pointerOrDefault(p *int, def int) int {
	if p != nil {
		return *p
	}

	return def
}

func patchConfigs(w http.ResponseWriter, r *http.Request) {
	general := &configSchema{}
	if err := render.DecodeJSON(r.Body, general); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, ErrBadRequest)
		return
	}

	if general.AllowLan != nil {
		P.SetAllowLan(*general.AllowLan)
	}

	ports := P.GetPorts()
	P.ReCreateHTTP(pointerOrDefault(general.Port, ports.Port))
	P.ReCreateSocks(pointerOrDefault(general.SocksPort, ports.SocksPort))
	P.ReCreateRedir(pointerOrDefault(general.RedirPort, ports.RedirPort))

	if general.Mode != nil {
		T.Instance().SetMode(*general.Mode)
	}

	if general.LogLevel != nil {
		log.SetLevel(*general.LogLevel)
	}

	w.WriteHeader(http.StatusNoContent)
}

type updateConfigRequest struct {
	Path    string `json:"path"`
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	req := updateConfigRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, ErrBadRequest)
		return
	}

	if !filepath.IsAbs(req.Path) {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, newError("path is not a absoluted path"))
		return
	}

	force := r.URL.Query().Get("force") == "true"
	cfg, err := executor.ParseWithPath(req.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, newError(err.Error()))
		return
	}

	executor.ApplyConfig(cfg, force)
	w.WriteHeader(http.StatusNoContent)
}
