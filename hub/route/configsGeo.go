package route

import (
	"net/http"
	"sync"

	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/log"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

var (
	updatingGeo  bool
	updateGeoMux sync.Mutex
)

func configGeoRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/", updateGeoDatabases)
	return r
}

func updateGeoDatabases(w http.ResponseWriter, r *http.Request) {
	updateGeoMux.Lock()

	if updatingGeo {
		updateGeoMux.Unlock()
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("updating..."))
		return
	}

	updatingGeo = true
	updateGeoMux.Unlock()

	go func() {
		defer func() {
			updatingGeo = false
		}()

		log.Warnln("[REST-API] updating GEO databases...")

		if err := config.UpdateGeoDatabases(); err != nil {
			log.Errorln("[REST-API] update GEO databases failed: %v", err)
			return
		}

		cfg, err := executor.ParseWithPath(constant.Path.Config())
		if err != nil {
			log.Errorln("[REST-API] update GEO databases failed: %v", err)
			return
		}

		log.Warnln("[REST-API] update GEO databases successful, apply config...")

		executor.ApplyConfig(cfg, false)
	}()

	render.NoContent(w, r)
}
