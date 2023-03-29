package route

import (
	"net/http"

	"github.com/Dreamacro/clash/hub/updater"
	"github.com/Dreamacro/clash/log"

	"github.com/go-chi/chi/v5"
)

func upgradeRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/", upgrade)
	return r
}

func upgrade(w http.ResponseWriter, r *http.Request) {
	// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/home/controlupdate.go#L108
	log.Infoln("start update")
	err := updater.Update()
	if err != nil {
		log.Errorln("err:%s", err)
		return
	}

	restart(w, r)
}
