package hub

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	log "github.com/sirupsen/logrus"
)

var (
	tun = tunnel.GetInstance()
)

type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

type Error struct {
	Error string `json:"error"`
}

func NewHub(addr string) {
	r := chi.NewRouter()

	r.Get("/traffic", traffic)
	r.Get("/logs", getLogs)

	err := http.ListenAndServe(addr, r)
	if err != nil {
		log.Fatalf("External controller error: %s", err.Error())
	}
}

func traffic(w http.ResponseWriter, r *http.Request) {
	render.Status(r, http.StatusOK)

	tick := time.NewTicker(time.Second)
	t := tun.Traffic()
	for range tick.C {
		up, down := t.Now()
		if err := json.NewEncoder(w).Encode(Traffic{
			Up:   up,
			Down: down,
		}); err != nil {
			break
		}
		w.(http.Flusher).Flush()
	}
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	src := tun.Log()
	sub, err := src.Subscribe()
	defer src.UnSubscribe(sub)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, Error{
			Error: err.Error(),
		})
	}
	render.Status(r, http.StatusOK)
	for elm := range sub {
		log := elm.(tunnel.Log)
		if err := json.NewEncoder(w).Encode(Log{
			Type:    log.Type(),
			Payload: log.Payload,
		}); err != nil {
			break
		}
		w.(http.Flusher).Flush()
	}
}
