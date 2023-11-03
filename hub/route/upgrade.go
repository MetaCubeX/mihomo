package route

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/updater"
	"github.com/metacubex/mihomo/log"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func upgradeRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/", upgradeCore)
	r.Post("/ui", updateUI)
	return r
}

func upgradeCore(w http.ResponseWriter, r *http.Request) {
	// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/home/controlupdate.go#L108
	log.Infoln("start update")
	execPath, err := os.Executable()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(fmt.Sprintf("getting path: %s", err)))
		return
	}

	err = updater.Update(execPath)
	if err != nil {
		log.Warnln("%s", err)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(fmt.Sprintf("%s", err)))
		return
	}

	render.JSON(w, r, render.M{"status": "ok"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go restartExecutable(execPath)
}

func updateUI(w http.ResponseWriter, r *http.Request) {
	err := config.UpdateUI()
	if err != nil {
		if errors.Is(err, config.ErrIncompleteConf) {
			log.Warnln("%s", err)
			render.Status(r, http.StatusNotImplemented)
			render.JSON(w, r, newError(fmt.Sprintf("%s", err)))
		} else {
			log.Warnln("%s", err)
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(fmt.Sprintf("%s", err)))
		}
		return
	}

	render.JSON(w, r, render.M{"status": "ok"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
